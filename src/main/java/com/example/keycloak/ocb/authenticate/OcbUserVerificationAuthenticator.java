package com.example.keycloak.ocb.authenticate;

import com.example.keycloak.ocb.authenticate.client.OcbClient;
import com.example.keycloak.ocb.authenticate.config.OcbVerificationConfig;
import com.example.keycloak.ocb.authenticate.model.ApiResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class OcbUserVerificationAuthenticator implements Authenticator {
    private static final Logger logger = Logger.getLogger(OcbUserVerificationAuthenticator.class);

    private static final String EXTERNAL_USERNAME = "EXTERNAL_USERNAME";
    private static final String EXTERNAL_PASSWORD = "EXTERNAL_PASSWORD";
    private static final String EXT_API_RESPONSE_CODE = "EXT_API_RESPONSE_CODE";
    private static final String EXT_API_RESPONSE_MESSAGE = "EXT_API_RESPONSE_MESSAGE";
    private static final String EXT_API_SUCCESS = "EXT_API_SUCCESS";

    // Session keys for next step
    private static final String EXTERNAL_VERIFICATION_COMPLETED = "EXTERNAL_VERIFICATION_COMPLETED";
    private static final String CUSTOMER_NUMBER = "CUSTOMER_NUMBER";
    private static final String USER_INFO_JSON = "USER_INFO_JSON";
    private static final String VERIFIED_USERNAME = "VERIFIED_USERNAME";

    public enum MessageType {
        SUCCESS, ERROR, INFO
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        logger.info("=== Starting ExternalUserVerificationAuthenticator ===");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        if (isAlreadyVerified(authSession)) {
            logger.info("External verification already completed, proceeding to next step");
            context.success();
            return;
        }

        String username = authSession.getAuthNote(EXTERNAL_USERNAME);
        String password = authSession.getAuthNote(EXTERNAL_PASSWORD);

        if (username != null && !username.isEmpty() && password != null && !password.isEmpty()) {
            logger.info("Found credentials in session, attempting verification");
            handleCredentialsVerification(context, username, password);
        } else {
            logger.info("No credentials found, showing login form");
            showLoginForm(context, null, MessageType.INFO);
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        logger.info("=== Processing external verification action ===");

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String username = formData.getFirst("username");
        String password = formData.getFirst("password");

        logger.infof("Form submission - Username: %s, Password provided: %s",
                username, password != null && !password.isEmpty());

        if (username == null || username.trim().isEmpty() ||
                password == null || password.trim().isEmpty()) {
            logger.warn("Username or password is empty");
            showLoginForm(context, "Vui lòng nhập đầy đủ tên đăng nhập và mật khẩu", MessageType.ERROR);
            return;
        }

        username = username.trim();
        password = password.trim();

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        authSession.setAuthNote(EXTERNAL_USERNAME, username);
        authSession.setAuthNote(EXTERNAL_PASSWORD, password);

        handleCredentialsVerification(context, username, password);
    }

    private boolean isAlreadyVerified(AuthenticationSessionModel session) {
        return "true".equals(session.getAuthNote(EXTERNAL_VERIFICATION_COMPLETED));
    }


    private boolean isNextStepEnabled(AuthenticationFlowContext context) {
        return context.getExecution().getFlowId() != null &&
                hasEnabledNextStep(context);
    }

    private boolean hasEnabledNextStep(AuthenticationFlowContext context) {
        try {
            List<AuthenticationExecutionModel> executions = context.getRealm()
                    .getAuthenticationExecutionsStream(context.getExecution().getFlowId())
                    .collect(Collectors.toList());

            int currentIndex = -1;
            for (int i = 0; i < executions.size(); i++) {
                if (executions.get(i).getId().equals(context.getExecution().getId())) {
                    currentIndex = i;
                    break;
                }
            }

            if (currentIndex >= 0 && currentIndex < executions.size() - 1) {
                for (int i = currentIndex + 1; i < executions.size(); i++) {
                    AuthenticationExecutionModel nextExec = executions.get(i);
                    if (nextExec.getRequirement() != AuthenticationExecutionModel.Requirement.DISABLED) {
                        return true;
                    }
                }
            }

            return false;
        } catch (Exception e) {
            logger.error("Error checking next step", e);
            return true;
        }
    }

    private void handleCredentialsVerification(AuthenticationFlowContext context, String username, String password) {
        logger.info("=== Handling credentials verification ===");
        logger.infof("Verifying credentials for username: %s", username);

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        OcbVerificationConfig config = OcbVerificationConfig.getConfig(context);

        if (!config.isValid()) {
            logger.error("External verification config is invalid");
            context.failure(AuthenticationFlowError.CLIENT_CREDENTIALS_SETUP_REQUIRED);
            return;
        }

        try {
            logger.info("Creating external API client for user verification");
            OcbClient apiClient = new OcbClient(
                    config.getApiUrl(),
                    config.getApiUsername(),
                    config.getApiPassword(),
                    config.getTimeout()
            );

            logger.infof("Calling external API to verify user: %s", username);
            ApiResponse userVerifyResponse = apiClient.verifyUser(username, password);

            logger.infof("External API response - Code: %s, Message: %s, Success: %s",
                    userVerifyResponse.getCode(),
                    userVerifyResponse.getMessage(),
                    userVerifyResponse.isSuccess());

            authSession.setAuthNote(EXT_API_RESPONSE_CODE,
                    userVerifyResponse.getCode() != null ? userVerifyResponse.getCode() : "");
            authSession.setAuthNote(EXT_API_RESPONSE_MESSAGE,
                    userVerifyResponse.getMessage() != null ? userVerifyResponse.getMessage() : "");
            authSession.setAuthNote(EXT_API_SUCCESS, String.valueOf(userVerifyResponse.isSuccess()));

            if (!userVerifyResponse.isSuccess()) {
                handleVerificationError(context, userVerifyResponse);
                return;
            }

            logger.info("User verification successful, extracting user info");
            Map<String, String> userInfo = userVerifyResponse.getUserInfo();

            if (userInfo == null || userInfo.isEmpty()) {
                logger.error("No user info returned from successful API call");
                showLoginForm(context, "Lỗi không xác định từ hệ thống", MessageType.ERROR);
                return;
            }

            String customerNumber = userInfo.get("customerNumber");
            if (customerNumber == null || customerNumber.isEmpty()) {
                logger.error("No customerNumber found in user verification response");
                showLoginForm(context, "Thông tin khách hàng không hợp lệ", MessageType.ERROR);
                return;
            }

            logger.infof("User info extracted - CustomerNumber: %s, Email: %s, Mobile: %s",
                    customerNumber, userInfo.get("email"), userInfo.get("mobile"));

            logger.info("Creating/updating user in Keycloak after successful verification");
            UserModel user = createOrUpdateUser(context, username, userInfo);
            if (user == null) {
                logger.error("Failed to create/update user in Keycloak");
                showLoginForm(context, "Lỗi tạo thông tin người dùng", MessageType.ERROR);
                return;
            }

            context.setUser(user);
            logger.infof("User context set for: %s", username);

            if (!isNextStepEnabled(context)) {
                logger.info("No next step enabled, completing authentication directly");
                cleanupSessionDirect(authSession);
                context.success();
                logger.infof("Authentication completed directly for user: %s", username);
                return;
            }

            storeDataForNextStep(authSession, username, customerNumber, userInfo);
            authSession.removeAuthNote(EXTERNAL_PASSWORD);

            logger.info("External verification completed successfully, proceeding to next step");
            context.success();

        } catch (Exception e) {
            logger.error("Unexpected error during credentials verification", e);
            showLoginForm(context, "Lỗi hệ thống. Vui lòng thử lại.", MessageType.ERROR);
        }
    }

    private UserModel createOrUpdateUser(AuthenticationFlowContext context, String username, Map<String, String> userInfo) {
        logger.info("=== Creating/updating user in Keycloak ===");

        try {
            UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), username);

            if (user == null) {
                logger.infof("Creating new user in Keycloak: %s", username);
                user = createUserInKeycloak(context, userInfo);
                if (user == null) {
                    logger.error("Failed to create user in Keycloak");
                    return null;
                }
            } else {
                logger.infof("Updating existing user in Keycloak: %s", username);
                updateUserInKeycloak(user, userInfo);
            }

            logger.infof("User created/updated successfully: %s (Customer: %s)",
                    username, userInfo.get("customerNumber"));
            return user;

        } catch (Exception e) {
            logger.error("Error creating/updating user in Keycloak", e);
            return null;
        }
    }

    private void cleanupSessionDirect(AuthenticationSessionModel authSession) {
        logger.info("Cleaning up session for direct login");

        String[] keysToRemove = {
                EXTERNAL_USERNAME, EXTERNAL_PASSWORD,
                EXT_API_RESPONSE_CODE, EXT_API_RESPONSE_MESSAGE, EXT_API_SUCCESS
        };

        for (String key : keysToRemove) {
            authSession.removeAuthNote(key);
        }
    }

    private UserModel createUserInKeycloak(AuthenticationFlowContext context, Map<String, String> userInfo) {
        try {
            logger.info("Creating new user in Keycloak with user info");

            RealmModel realm = context.getRealm();
            UserModel newUser = context.getSession().users().addUser(realm, userInfo.get("username"));

            setUserAttributes(newUser, userInfo);

            logger.infof("User created in Keycloak successfully: %s (Customer: %s)",
                    newUser.getUsername(), userInfo.get("customerNumber"));

            return newUser;
        } catch (Exception e) {
            logger.error("Error creating user in Keycloak", e);
            return null;
        }
    }

    private void updateUserInKeycloak(UserModel user, Map<String, String> userInfo) {
        try {
            logger.info("Updating existing user in Keycloak");
            setUserAttributes(user, userInfo);
            logger.infof("User updated in Keycloak successfully: %s", user.getUsername());
        } catch (Exception e) {
            logger.error("Error updating user in Keycloak", e);
        }
    }

    private void setUserAttributes(UserModel user, Map<String, String> userInfo) {
        user.setEnabled(true);
        user.setEmail(userInfo.get("email"));

        String fullName = userInfo.get("fullName");
        if (fullName != null && !fullName.isEmpty()) {
            String[] names = fullName.split(" ", 2);
            if (names.length > 0) {
                user.setFirstName(names[0]);
                if (names.length > 1) {
                    user.setLastName(names[1]);
                }
            }
        }

        user.setSingleAttribute("mobile", userInfo.get("mobile"));
        user.setSingleAttribute("customerNumber", userInfo.get("customerNumber"));
        user.setSingleAttribute("externalVerified", "true");
        user.setSingleAttribute("lastExternalVerification", String.valueOf(System.currentTimeMillis()));
    }

    private void storeDataForNextStep(AuthenticationSessionModel authSession, String username,
                                      String customerNumber, Map<String, String> userInfo) {
        try {
            authSession.setAuthNote(EXTERNAL_VERIFICATION_COMPLETED, "true");
            authSession.setAuthNote(VERIFIED_USERNAME, username);
            authSession.setAuthNote(CUSTOMER_NUMBER, customerNumber);

            ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            String userInfoJson = mapper.writeValueAsString(userInfo);
            authSession.setAuthNote(USER_INFO_JSON, userInfoJson);

            logger.infof("Data stored for next step - Username: %s, CustomerNumber: %s", username, customerNumber);

        } catch (Exception e) {
            logger.error("Failed to store user info for next step", e);
            throw new RuntimeException("Failed to serialize user data", e);
        }
    }

    private void handleVerificationError(AuthenticationFlowContext context, ApiResponse userVerifyResponse) {
        logger.warnf("User verification failed. Code: %s, Message: %s",
                userVerifyResponse.getCode(), userVerifyResponse.getMessage());

        String errorMessage = userVerifyResponse.getMessage();
        if (errorMessage == null || errorMessage.isEmpty()) {
            errorMessage = "Thông tin đăng nhập không chính xác";
        }

        showLoginForm(context, errorMessage, MessageType.ERROR);
    }

    private void showLoginForm(AuthenticationFlowContext context, String message, MessageType messageType) {
        logger.info("Showing external verification login form");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String username = authSession.getAuthNote(EXTERNAL_USERNAME);

        LoginFormsProvider form = context.form()
                .setAttribute("showCredentialsForm", true)
                .setAttribute("showOtpForm", false)
                .setAttribute("showOtpField", false)
                .setAttribute("submitAction", "verify_credentials")
                .setAttribute("submitButtonText", "Xác thực thông tin")
                .setAttribute("username", username != null ? username : "")
                .setAttribute("backAction", "")
                .setAttribute("backButtonText", "");

        addApiResponseAttributes(form, authSession);

        if (message != null && !message.isEmpty()) {
            logger.infof("Showing login form with message (type: %s): %s", messageType, message);

            switch (messageType) {
                case ERROR:
                    form.setError(message);
                    break;
                case SUCCESS:
                case INFO:
                    form.setInfo(message);
                    break;
            }
        }

        Response challengeResponse = form.createLoginUsernamePassword();
        context.challenge(challengeResponse);
    }

    private void addApiResponseAttributes(org.keycloak.forms.login.LoginFormsProvider form,
                                          AuthenticationSessionModel authSession) {
        form.setAttribute("extApiResponseCode", getSessionAttributeSafely(authSession, EXT_API_RESPONSE_CODE));
        form.setAttribute("extApiResponseMessage", getSessionAttributeSafely(authSession, EXT_API_RESPONSE_MESSAGE));
        form.setAttribute("extApiSuccess", getSessionAttributeSafely(authSession, EXT_API_SUCCESS));
        form.setAttribute("otpApiResponseCode", "");
        form.setAttribute("otpApiResponseMessage", "");
        form.setAttribute("otpApiSuccess", "");
        form.setAttribute("otpVerifyResponseCode", "");
        form.setAttribute("otpVerifyResponseMessage", "");
        form.setAttribute("otpVerifySuccess", "");
        form.setAttribute("otpState", "");
    }

    private String getSessionAttributeSafely(AuthenticationSessionModel session, String key) {
        String value = session.getAuthNote(key);
        return value != null ? value : "";
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}