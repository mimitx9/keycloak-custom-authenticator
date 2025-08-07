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
import org.keycloak.authentication.AuthenticationFlowException;
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
        logger.infof("=== Starting OcbUserVerificationAuthenticator - execution ID: %s ===",
                context.getExecution().getId());

        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        if (isAlreadyVerified(authSession)) {
            logger.info("External verification already completed, setting user and proceeding");

            // Try to set user from previous verification
            String verifiedUsername = authSession.getAuthNote(VERIFIED_USERNAME);
            if (verifiedUsername != null && context.getUser() == null) {
                UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), verifiedUsername);
                if (user != null) {
                    logger.infof("Setting previously verified user: %s", verifiedUsername);
                    try {
                        context.setUser(user);
                    } catch (Exception e) {
                        logger.warnf("Could not set user %s, might already be set: %s", verifiedUsername, e.getMessage());
                    }
                }
            }

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
        logger.infof("=== Processing external verification action - execution ID: %s ===",
                context.getExecution().getId());

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
        String completed = session.getAuthNote(EXTERNAL_VERIFICATION_COMPLETED);
        boolean isVerified = "true".equals(completed);
        logger.infof("Checking if already verified: %s", isVerified);
        return isVerified;
    }

    private void handleCredentialsVerification(AuthenticationFlowContext context, String username, String password) {
        logger.info("=== Handling credentials verification ===");
        logger.infof("Verifying credentials for username: %s", username);

        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        try {
            OcbVerificationConfig config = OcbVerificationConfig.getConfig(context);

            if (!config.isValid()) {
                logger.error("External verification config is invalid");
                context.failure(AuthenticationFlowError.CLIENT_CREDENTIALS_SETUP_REQUIRED);
                return;
            }

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

            // Store API response in session
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
                context.failure(AuthenticationFlowError.INTERNAL_ERROR);
                return;
            }

            // Store additional info in session for next steps
            authSession.setAuthNote(CUSTOMER_NUMBER, customerNumber);
            authSession.setAuthNote(VERIFIED_USERNAME, username);

            // Store user info as JSON for next steps if needed
            try {
                ObjectMapper mapper = new ObjectMapper();
                authSession.setAuthNote(USER_INFO_JSON, mapper.writeValueAsString(userInfo));
            } catch (Exception e) {
                logger.warn("Failed to store user info as JSON, continuing anyway", e);
            }

            // Clean up password from session
            authSession.removeAuthNote(EXTERNAL_PASSWORD);

            // Mark verification as completed BEFORE calling success
            authSession.setAuthNote(EXTERNAL_VERIFICATION_COMPLETED, "true");

            // Set the authenticated user - but only if not already set
            if (context.getUser() == null) {
                logger.infof("Setting authenticated user: %s", user.getUsername());
                try {
                    context.setUser(user);
                } catch (AuthenticationFlowException e) {
                    logger.warnf("Could not set user %s, might already be set: %s", user.getUsername(), e.getMessage());
                    // Continue anyway, user might already be set by previous execution
                }
            } else {
                logger.infof("User already set in context: %s", context.getUser().getUsername());
            }

            logger.info("External verification completed successfully, proceeding to next step");
            context.success();

        } catch (Exception e) {
            logger.error("Unexpected error during credentials verification", e);
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
        }
    }

    private UserModel createOrUpdateUser(AuthenticationFlowContext context, String username, Map<String, String> userInfo) {
        logger.info("=== Creating/updating user in Keycloak ===");

        try {
            RealmModel realm = context.getRealm();
            KeycloakSession session = context.getSession();

            UserModel user = session.users().getUserByUsername(realm, username);

            if (user == null) {
                logger.infof("Creating new user in Keycloak: %s", username);
                user = createUserInKeycloak(context, username, userInfo);
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

    private UserModel createUserInKeycloak(AuthenticationFlowContext context, String username, Map<String, String> userInfo) {
        try {
            logger.info("Creating new user in Keycloak with user info");
            logger.infof("Creating user with username: %s", username);

            // Validate username again
            if (username == null || username.trim().isEmpty()) {
                logger.error("Cannot create user: username is null or empty");
                return null;
            }

            RealmModel realm = context.getRealm();
            KeycloakSession session = context.getSession();

            // Check if user already exists (double check)
            UserModel existingUser = session.users().getUserByUsername(realm, username.trim());
            if (existingUser != null) {
                logger.infof("User already exists during creation attempt: %s", username);
                updateUserInKeycloak(existingUser, userInfo);
                return existingUser;
            }

            // Create new user
            UserModel newUser = session.users().addUser(realm, username.trim());
            if (newUser == null) {
                logger.error("Failed to add user to Keycloak");
                return null;
            }

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
            logger.infof("Updating existing user in Keycloak: %s", user.getUsername());
            setUserAttributes(user, userInfo);
            logger.infof("User updated in Keycloak successfully: %s", user.getUsername());
        } catch (Exception e) {
            logger.error("Error updating user in Keycloak", e);
            throw e; // Re-throw to be handled by caller
        }
    }

    private void setUserAttributes(UserModel user, Map<String, String> userInfo) {
        try {
            user.setEnabled(true);

            // Set email if provided
            String email = userInfo.get("email");

            // Set names
            String fullName = userInfo.get("fullName");
            if (fullName != null && !fullName.trim().isEmpty()) {
                String[] names = fullName.trim().split("\\s+", 2);
                if (names.length > 0) {
                    user.setFirstName(names[0]);
                    if (names.length > 1) {
                        user.setLastName(names[1]);
                    }
                }
            }

            setUserAttributeIfNotEmpty(user, "email", email);
            setUserAttributeIfNotEmpty(user, "mobile", userInfo.get("mobile"));
            setUserAttributeIfNotEmpty(user, "customerNumber", userInfo.get("customerNumber"));
            user.setSingleAttribute("externalVerified", "true");
            user.setSingleAttribute("lastExternalVerification", String.valueOf(System.currentTimeMillis()));

            logger.infof("Set attributes for user: %s", user.getUsername());

        } catch (Exception e) {
            logger.error("Error setting user attributes", e);
            throw e;
        }
    }

    private void setUserAttributeIfNotEmpty(UserModel user, String attributeName, String value) {
        if (value != null && !value.trim().isEmpty()) {
            user.setSingleAttribute(attributeName, value.trim());
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

    private void addApiResponseAttributes(LoginFormsProvider form, AuthenticationSessionModel authSession) {
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
        // No required actions needed
    }

    @Override
    public void close() {
        // No resources to close
    }
}