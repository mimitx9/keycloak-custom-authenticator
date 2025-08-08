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

    public enum MessageType {
        SUCCESS, ERROR, INFO
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        logger.info("Starting OCB unified authentication - showing login form");
        showLoginForm(context, null, MessageType.INFO);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        logger.info("Processing login form submission");

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        // Handle cancel action
        if (formData.containsKey("cancel")) {
            logger.info("Login cancelled by user");
            context.cancelLogin();
            return;
        }

        String username = formData.getFirst("username");
        String password = formData.getFirst("password");

        logger.infof("Form submission - Username: %s, Password provided: %s",
                username, password != null && !password.isEmpty());

        // Validate input
        if (username == null || username.trim().isEmpty()) {
            logger.warn("Username is empty");
            showLoginForm(context, "Vui lòng nhập tên đăng nhập.", MessageType.ERROR);
            return;
        }

        if (password == null || password.trim().isEmpty()) {
            logger.warn("Password is empty");
            showLoginForm(context, "Vui lòng nhập mật khẩu.", MessageType.ERROR);
            return;
        }

        // Proceed with verification and authentication
        handleAuthentication(context, username.trim(), password.trim());
    }

    private void handleAuthentication(AuthenticationFlowContext context, String username, String password) {
        logger.infof("Authenticating user: %s", username);

        try {
            // Get and validate configuration
            OcbVerificationConfig config = OcbVerificationConfig.getConfig(context);
            if (!config.isValid()) {
                logger.error("External verification config is invalid");
                context.failure(AuthenticationFlowError.CLIENT_CREDENTIALS_SETUP_REQUIRED);
                return;
            }

            // Create API client and verify user
            logger.info("Calling external API for user verification");
            OcbClient apiClient = new OcbClient(
                    config.getApiUrl(),
                    config.getApiUsername(),
                    config.getApiPassword(),
                    config.getTimeout()
            );

            ApiResponse verifyResponse = apiClient.verifyUser(username, password);

            logger.infof("External API response - Code: %s, Message: %s, Success: %s",
                    verifyResponse.getCode(),
                    verifyResponse.getMessage(),
                    verifyResponse.isSuccess());

            if (!verifyResponse.isSuccess()) {
                handleAuthenticationFailure(context, verifyResponse);
                return;
            }

            handleAuthenticationSuccess(context, username, verifyResponse);

        } catch (Exception e) {
            logger.error("Unexpected error during authentication", e);
            showLoginForm(context, "Đã xảy ra lỗi hệ thống. Vui lòng thử lại.", MessageType.ERROR, null);
        }
    }

    private void handleAuthenticationSuccess(AuthenticationFlowContext context, String username, ApiResponse verifyResponse) {
        logger.info("External verification successful, processing user");

        Map<String, String> userInfo = verifyResponse.getUserInfo();

        if (userInfo == null || userInfo.isEmpty()) {
            logger.error("No user info returned from successful API call");
            showLoginForm(context, "Lỗi không xác định từ hệ thống", MessageType.ERROR, verifyResponse);
            return;
        }

        String customerNumber = userInfo.get("customerNumber");
        logger.infof("User info - CustomerNumber: %s, Email: %s, Mobile: %s",
                customerNumber, userInfo.get("email"), userInfo.get("mobile"));

        UserModel user = createOrUpdateUser(context, username, userInfo);
        if (user == null) {
            logger.error("Failed to create/update user in Keycloak");
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
            return;
        }

        context.setUser(user);
        logger.infof("Authentication completed successfully for user: %s", username);
        context.success();
    }

    private void handleAuthenticationFailure(AuthenticationFlowContext context, ApiResponse verifyResponse) {
        logger.warnf("Authentication failed. Code: %s, Message: %s",
                verifyResponse.getCode(), verifyResponse.getMessage());

        String errorMessage = verifyResponse.getMessage();
        if (errorMessage == null || errorMessage.isEmpty()) {
            errorMessage = "Thông tin đăng nhập không chính xác";
        }
        showLoginForm(context, errorMessage, MessageType.ERROR, verifyResponse);
    }

    private UserModel createOrUpdateUser(AuthenticationFlowContext context, String username, Map<String, String> userInfo) {
        logger.infof("Creating/updating user in Keycloak: %s", username);

        try {
            RealmModel realm = context.getRealm();
            KeycloakSession session = context.getSession();

            UserModel user = session.users().getUserByUsername(realm, username);

            if (user == null) {
                logger.infof("Creating new user: %s", username);
                user = session.users().addUser(realm, username);
                if (user == null) {
                    logger.error("Failed to create user in Keycloak");
                    return null;
                }
            } else {
                logger.infof("Updating existing user: %s", username);
            }

            // Set user attributes
            setUserAttributes(user, userInfo);

            logger.infof("User processed successfully: %s (Customer: %s)",
                    username, userInfo.get("customerNumber"));
            return user;

        } catch (Exception e) {
            logger.error("Error processing user in Keycloak", e);
            return null;
        }
    }

    private void setUserAttributes(UserModel user, Map<String, String> userInfo) {
        user.setEnabled(true);

        // Set names from fullName
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

        // Set custom attributes
        setAttributeIfNotEmpty(user, "email", userInfo.get("email"));
        setAttributeIfNotEmpty(user, "mobile", userInfo.get("mobile"));
        setAttributeIfNotEmpty(user, "customerNumber", userInfo.get("customerNumber"));
        user.setSingleAttribute("externalVerified", "true");
        user.setSingleAttribute("lastExternalVerification", String.valueOf(System.currentTimeMillis()));

        logger.infof("Set attributes for user: %s", user.getUsername());
    }

    private void setAttributeIfNotEmpty(UserModel user, String attributeName, String value) {
        if (value != null && !value.trim().isEmpty()) {
            user.setSingleAttribute(attributeName, value.trim());
        }
    }

    private void showLoginForm(AuthenticationFlowContext context, String message, MessageType messageType) {
        showLoginForm(context, message, messageType, null);
    }

    private void showLoginForm(AuthenticationFlowContext context, String message, MessageType messageType, ApiResponse apiResponse) {
        logger.info("Showing login form");

        LoginFormsProvider form = context.form()
                .setAttribute("submitButtonText", "Đăng nhập");

        // Set API response attributes for frontend
        if (apiResponse != null) {
            form.setAttribute("extApiResponseCode", apiResponse.getCode() != null ? apiResponse.getCode() : "");
            form.setAttribute("extApiResponseMessage", apiResponse.getMessage() != null ? apiResponse.getMessage() : "");
            form.setAttribute("extApiSuccess", String.valueOf(apiResponse.isSuccess()));
        } else {
            form.setAttribute("extApiResponseCode", "");
            form.setAttribute("extApiResponseMessage", "");
            form.setAttribute("extApiSuccess", "");
        }

        if (message != null && !message.isEmpty()) {
            logger.infof("Showing message (type: %s): %s", messageType, message);

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