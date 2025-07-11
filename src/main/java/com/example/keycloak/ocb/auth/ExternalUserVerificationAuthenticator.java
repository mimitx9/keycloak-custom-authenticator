package com.example.keycloak.ocb.auth;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

public class ExternalUserVerificationAuthenticator implements Authenticator {
    private static final Logger logger = Logger.getLogger(ExternalUserVerificationAuthenticator.class);

    // Action constants
    private static final String ACTION_VERIFY_OTP = "verify_otp";
    private static final String ACTION_BACK_TO_LOGIN = "back_to_login";

    // Success codes
    private static final Set<String> SUCCESS_CODES = Set.of("00", "0", "0000", "SUCCESS");

    // Message types
    public enum MessageType {
        SUCCESS, ERROR, INFO
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        logger.info("=== Starting ExternalUserVerificationAuthenticator ===");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String currentState = authSession.getAuthNote("AUTH_STATE");

        logger.infof("Current authentication state: %s", currentState);

        // Check if we have credentials from CustomUsernamePasswordForm
        String username = authSession.getAuthNote("EXTERNAL_USERNAME");
        String password = authSession.getAuthNote("EXTERNAL_PASSWORD");

        logger.infof("Credentials from session - username: %s, password provided: %s",
                username, password != null && !password.isEmpty());

        if (currentState == null || currentState.isEmpty()) {
            // First time: verify credentials if available
            if (username != null && !username.isEmpty() && password != null && !password.isEmpty()) {
                logger.info("Found credentials in session, proceeding with verification");
                handleCredentialsVerificationFromSession(context, username, password);
            } else {
                logger.warn("No credentials found in session, this should not happen");
                context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
            }
            return;
        }

        switch (currentState) {
            case "CREDENTIALS_VERIFIED":
                logger.info("Credentials already verified, showing OTP form");
                showOtpForm(context, null, MessageType.INFO);
                break;
            case "OTP_SENT":
                logger.info("OTP already sent, showing OTP form");
                showOtpForm(context, null, MessageType.INFO);
                break;
            default:
                logger.warnf("Unknown state: %s, failing authentication", currentState);
                context.failure(AuthenticationFlowError.INTERNAL_ERROR);
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        logger.info("=== Processing form action in ExternalUserVerificationAuthenticator ===");

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String action = formData.getFirst("action");

        logger.infof("Form action received: %s", action);

        if (ACTION_VERIFY_OTP.equals(action)) {
            handleOtpVerification(context, formData);
        } else if (ACTION_BACK_TO_LOGIN.equals(action)) {
            handleBackToLogin(context);
        } else {
            logger.warnf("Unknown action: %s", action);
            showOtpForm(context, "Invalid action, please try again", MessageType.ERROR);
        }
    }

    private void handleCredentialsVerificationFromSession(AuthenticationFlowContext context, String username, String password) {
        logger.info("=== Handling credentials verification from session ===");

        logger.infof("Verifying credentials for username: %s", username);

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        ExternalVerificationConfig config = ExternalVerificationConfig.getConfig(context);

        if (!config.isValid()) {
            logger.error("External verification config is invalid");
            context.failure(AuthenticationFlowError.CLIENT_CREDENTIALS_SETUP_REQUIRED);
            return;
        }

        try {
            logger.info("Creating external API client for user verification");
            ExternalApiClient apiClient = new ExternalApiClient(
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

            authSession.setAuthNote("EXT_API_RESPONSE_CODE", userVerifyResponse.getCode() != null ? userVerifyResponse.getCode() : "");
            authSession.setAuthNote("EXT_API_RESPONSE_MESSAGE", userVerifyResponse.getMessage() != null ? userVerifyResponse.getMessage() : "");
            authSession.setAuthNote("EXT_API_SUCCESS", String.valueOf(userVerifyResponse.isSuccess()));

            if (!userVerifyResponse.isSuccess()) {
                logger.warnf("User verification failed for %s. Code: %s, Message: %s",
                        username, userVerifyResponse.getCode(), userVerifyResponse.getMessage());

                // Clear session and force restart
                resetAuthenticationState(authSession);
                context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
                return;
            }

            logger.info("User verification successful, extracting user info");
            Map<String, String> userInfo = userVerifyResponse.getUserInfo();

            if (userInfo == null || userInfo.isEmpty()) {
                logger.error("No user info returned from successful API call");
                resetAuthenticationState(authSession);
                context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
                return;
            }

            String customerNumber = userInfo.get("customerNumber");
            if (customerNumber == null || customerNumber.isEmpty()) {
                logger.error("No customerNumber found in user verification response");
                resetAuthenticationState(authSession);
                context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
                return;
            }

            logger.infof("User info extracted - CustomerNumber: %s, Email: %s, Mobile: %s",
                    customerNumber, userInfo.get("email"), userInfo.get("mobile"));

            // Update session with verified data
            authSession.setAuthNote("CUSTOMER_NUMBER", customerNumber);

            try {
                String userInfoJson = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(userInfo);
                authSession.setAuthNote("USER_INFO_JSON", userInfoJson);
                logger.info("User info stored in session successfully");
            } catch (Exception e) {
                logger.error("Failed to serialize user info to JSON", e);
            }

            authSession.setAuthNote("AUTH_STATE", "CREDENTIALS_VERIFIED");
            createOtpTransaction(context, userInfo, config);

        } catch (Exception e) {
            logger.error("Unexpected error during credentials verification", e);
            resetAuthenticationState(authSession);
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
        }
    }

    private void createOtpTransaction(AuthenticationFlowContext context, Map<String, String> userInfo, ExternalVerificationConfig config) {
        logger.info("=== Creating OTP transaction ===");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String customerNumber = userInfo.get("customerNumber");

        if (!config.isOtpConfigValid()) {
            logger.error("OTP configuration is invalid");
            resetAuthenticationState(authSession);
            context.failure(AuthenticationFlowError.CLIENT_CREDENTIALS_SETUP_REQUIRED);
            return;
        }

        try {
            logger.info("Creating Smart OTP client");
            SmartOtpClient otpClient = new SmartOtpClient(
                    config.getOtpUrl(),
                    config.getOtpApiKey(),
                    config.getTimeout()
            );

            String transactionId = UUID.randomUUID().toString();
            String userId = "OCB_" + customerNumber;

            logger.infof("Creating OTP transaction - UserId: %s, TransactionId: %s", userId, transactionId);

            OtpResponse otpResponse = otpClient.createTransaction(
                    userId,
                    transactionId,
                    config.getTransactionData(),
                    config.getTransactionTypeId(),
                    config.getChallenge(),
                    config.getCallbackUrl(),
                    config.getOnline(),
                    config.getPush(),
                    config.getNotificationTitle(),
                    config.getNotificationBody(),
                    config.getEsignerTypeId(),
                    config.getChannelId()
            );

            // Log OTP API response
            logger.infof("OTP API response - Code: %s, Message: %s, Success: %s",
                    otpResponse.getCode(), otpResponse.getMessage(), otpResponse.isSuccess());

            // Store OTP response in session
            authSession.setAuthNote("TRANSACTION_ID", transactionId);
            authSession.setAuthNote("USER_ID", userId);
            authSession.setAuthNote("OTP_API_RESPONSE_CODE", otpResponse.getCode() != null ? otpResponse.getCode() : "");
            authSession.setAuthNote("OTP_API_RESPONSE_MESSAGE", otpResponse.getMessage() != null ? otpResponse.getMessage() : "");
            authSession.setAuthNote("OTP_API_SUCCESS", String.valueOf(otpResponse.isSuccess()));

            if (!otpResponse.isSuccess()) {
                logger.warnf("OTP creation failed. Code: %s, Message: %s",
                        otpResponse.getCode(), otpResponse.getMessage());

                // Reset to initial state on OTP creation failure
                resetAuthenticationState(authSession);
                context.failure(AuthenticationFlowError.INTERNAL_ERROR);
                return;
            }

            logger.info("OTP transaction created successfully");
            authSession.setAuthNote("AUTH_STATE", "OTP_SENT");

            // Use OTP API success message directly
            String successMessage = otpResponse.getMessage();
            if (successMessage == null || successMessage.isEmpty()) {
                successMessage = "OTP sent successfully";
            }

            showOtpForm(context, successMessage, MessageType.SUCCESS);

        } catch (Exception e) {
            logger.error("Error creating OTP transaction", e);
            resetAuthenticationState(authSession);
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
        }
    }

    private void handleOtpVerification(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        logger.info("=== Handling OTP verification ===");

        String otpNumber = formData.getFirst("otp");

        if (otpNumber == null || otpNumber.trim().isEmpty()) {
            logger.warn("OTP code is empty");
            showOtpForm(context, "OTP is required", MessageType.ERROR);
            return;
        }

        logger.infof("Verifying OTP code: %s", otpNumber.substring(0, Math.min(2, otpNumber.length())) + "***");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String transactionId = authSession.getAuthNote("TRANSACTION_ID");
        String userId = authSession.getAuthNote("USER_ID");
        String customerNumber = authSession.getAuthNote("CUSTOMER_NUMBER");

        if (transactionId == null || userId == null || customerNumber == null) {
            logger.errorf("Missing transaction information in session - TransactionId: %s, UserId: %s, CustomerNumber: %s",
                    transactionId, userId, customerNumber);
            resetAuthenticationState(authSession);
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
            return;
        }

        logger.infof("OTP verification context - UserId: %s, TransactionId: %s", userId, transactionId);

        ExternalVerificationConfig config = ExternalVerificationConfig.getConfig(context);

        try {
            logger.info("Creating Smart OTP client for verification");
            SmartOtpClient otpClient = new SmartOtpClient(
                    config.getOtpUrl(),
                    config.getOtpApiKey(),
                    config.getTimeout()
            );

            logger.info("Calling OTP verification API");
            OtpResponse otpVerifyResponse = otpClient.verifyOtp(userId, otpNumber, transactionId);

            // Log OTP verification response
            logger.infof("OTP verification response - Code: %s, Message: %s, Success: %s",
                    otpVerifyResponse.getCode(), otpVerifyResponse.getMessage(), otpVerifyResponse.isSuccess());

            // Update session with verification response
            authSession.setAuthNote("OTP_VERIFY_RESPONSE_CODE", otpVerifyResponse.getCode() != null ? otpVerifyResponse.getCode() : "");
            authSession.setAuthNote("OTP_VERIFY_RESPONSE_MESSAGE", otpVerifyResponse.getMessage() != null ? otpVerifyResponse.getMessage() : "");
            authSession.setAuthNote("OTP_VERIFY_SUCCESS", String.valueOf(otpVerifyResponse.isSuccess()));

            if (!otpVerifyResponse.isSuccess()) {
                logger.warnf("OTP verification failed. Code: %s, Message: %s",
                        otpVerifyResponse.getCode(), otpVerifyResponse.getMessage());

                // Use OTP verify API response message directly
                String errorMessage = otpVerifyResponse.getMessage();
                if (errorMessage == null || errorMessage.isEmpty()) {
                    errorMessage = "OTP verify failed. Code: " + otpVerifyResponse.getCode();
                }

                showOtpForm(context, errorMessage, MessageType.ERROR);
                return;
            }

            logger.info("OTP verification successful, completing authentication");

            String userInfoJson = authSession.getAuthNote("USER_INFO_JSON");
            Map<String, String> userInfo = null;

            if (userInfoJson != null) {
                try {
                    userInfo = new com.fasterxml.jackson.databind.ObjectMapper()
                            .readValue(userInfoJson, Map.class);
                    logger.info("User info retrieved from session successfully");
                } catch (Exception e) {
                    logger.error("Failed to deserialize user info from session", e);
                }
            }

            if (userInfo == null || userInfo.isEmpty()) {
                logger.error("No user info found in session");
                resetAuthenticationState(authSession);
                context.failure(AuthenticationFlowError.INTERNAL_ERROR);
                return;
            }

            String username = authSession.getAuthNote("EXTERNAL_USERNAME");
            UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), username);

            if (user == null) {
                logger.infof("Creating new user in Keycloak: %s", username);
                user = createUserInKeycloak(context, userInfo);
                if (user == null) {
                    logger.error("Failed to create user in Keycloak");
                    resetAuthenticationState(authSession);
                    context.failure(AuthenticationFlowError.INTERNAL_ERROR);
                    return;
                }
                logger.infof("User created successfully in Keycloak: %s", user.getUsername());
            } else {
                logger.infof("Updating existing user in Keycloak: %s", username);
                updateUserInKeycloak(user, userInfo);
                logger.infof("User updated successfully in Keycloak: %s", user.getUsername());
            }

            cleanupAuthenticationSession(authSession);
            context.setUser(user);
            context.success();

            logger.infof("Authentication completed successfully for user: %s", username);

        } catch (Exception e) {
            logger.error("Error during OTP verification", e);
            showOtpForm(context, "OTP verification error: " + e.getMessage(), MessageType.ERROR);
        }
    }

    private void handleBackToLogin(AuthenticationFlowContext context) {
        logger.info("=== Handling back to login action ===");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        resetAuthenticationState(authSession);

        // Simply show the initial login form with fresh state
        logger.info("Showing initial login form after back action");

        org.keycloak.forms.login.LoginFormsProvider form = context.form()
                .setAttribute("showCredentialsForm", true)
                .setAttribute("showOtpForm", false)
                .setAttribute("submitAction", "verify_credentials") // This will be handled by CustomUsernamePasswordForm
                .setAttribute("submitButtonText", "Xác thực thông tin");

        Response challengeResponse = form.createLoginUsernamePassword();
        context.challenge(challengeResponse);
    }

    private void showLoginFormWithRestart(AuthenticationFlowContext context) {
        logger.info("Showing login form for restart");

        // Clear all session state first
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        resetAuthenticationState(authSession);

        // Force a fresh start by creating error page that redirects
        Response response = context.form()
                .setError("Session expired. Please login again.")
                .createErrorPage(Response.Status.UNAUTHORIZED);

        context.challenge(response);
    }

    private void showOtpForm(AuthenticationFlowContext context, String message, MessageType messageType) {
        logger.info("Showing OTP form");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String username = authSession.getAuthNote("EXTERNAL_USERNAME");

        org.keycloak.forms.login.LoginFormsProvider form = context.form()
                .setAttribute("showCredentialsForm", false)
                .setAttribute("showOtpForm", true)
                .setAttribute("username", username)
                .setAttribute("submitAction", ACTION_VERIFY_OTP)
                .setAttribute("submitButtonText", "Đăng nhập")
                .setAttribute("backAction", ACTION_BACK_TO_LOGIN)
                .setAttribute("backButtonText", "Quay lại đăng nhập");

        if (message != null && !message.isEmpty()) {
            logger.infof("Showing OTP form with message (type: %s): %s", messageType, message);

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

        addDebugAttributes(form, authSession);

        Response challengeResponse = form.createLoginUsernamePassword();
        context.challenge(challengeResponse);
    }

    private void addDebugAttributes(org.keycloak.forms.login.LoginFormsProvider form, AuthenticationSessionModel authSession) {
        if (authSession != null) {
            form.setAttribute("extApiResponseCode", authSession.getAuthNote("EXT_API_RESPONSE_CODE"))
                    .setAttribute("extApiResponseMessage", authSession.getAuthNote("EXT_API_RESPONSE_MESSAGE"))
                    .setAttribute("extApiSuccess", authSession.getAuthNote("EXT_API_SUCCESS"))
                    .setAttribute("otpApiResponseCode", authSession.getAuthNote("OTP_API_RESPONSE_CODE"))
                    .setAttribute("otpApiResponseMessage", authSession.getAuthNote("OTP_API_RESPONSE_MESSAGE"))
                    .setAttribute("otpApiSuccess", authSession.getAuthNote("OTP_API_SUCCESS"))
                    .setAttribute("authState", authSession.getAuthNote("AUTH_STATE"));
        }
    }

    private void resetAuthenticationState(AuthenticationSessionModel authSession) {
        logger.info("Resetting authentication state");

        authSession.removeAuthNote("AUTH_STATE");
        authSession.removeAuthNote("EXTERNAL_USERNAME");
        authSession.removeAuthNote("EXTERNAL_PASSWORD");
        authSession.removeAuthNote("EXTERNAL_OTP");
        authSession.removeAuthNote("TRANSACTION_ID");
        authSession.removeAuthNote("USER_ID");
        authSession.removeAuthNote("CUSTOMER_NUMBER");
        authSession.removeAuthNote("USER_INFO_JSON");
        authSession.removeAuthNote("EXT_API_RESPONSE_CODE");
        authSession.removeAuthNote("EXT_API_RESPONSE_MESSAGE");
        authSession.removeAuthNote("EXT_API_SUCCESS");
        authSession.removeAuthNote("OTP_API_RESPONSE_CODE");
        authSession.removeAuthNote("OTP_API_RESPONSE_MESSAGE");
        authSession.removeAuthNote("OTP_API_SUCCESS");
        authSession.removeAuthNote("OTP_VERIFY_RESPONSE_CODE");
        authSession.removeAuthNote("OTP_VERIFY_RESPONSE_MESSAGE");
        authSession.removeAuthNote("OTP_VERIFY_SUCCESS");
        authSession.removeAuthNote("EXT_VERIFY_CHALLENGE_STATE");
    }

    private void cleanupAuthenticationSession(AuthenticationSessionModel authSession) {
        logger.info("Cleaning up authentication session");
        authSession.removeAuthNote("EXTERNAL_PASSWORD");
        authSession.removeAuthNote("EXTERNAL_OTP");
        authSession.removeAuthNote("TRANSACTION_ID");
        authSession.removeAuthNote("USER_ID");
        authSession.removeAuthNote("USER_INFO_JSON");
    }

    private UserModel createUserInKeycloak(AuthenticationFlowContext context, Map<String, String> userInfo) {
        try {
            logger.info("Creating new user in Keycloak with user info");

            RealmModel realm = context.getRealm();
            UserModel newUser = context.getSession().users().addUser(realm, userInfo.get("username"));

            newUser.setEnabled(true);
            newUser.setEmail(userInfo.get("email"));

            String fullName = userInfo.get("fullName");
            if (fullName != null && !fullName.isEmpty()) {
                String[] names = fullName.split(" ", 2);
                if (names.length > 0) {
                    newUser.setFirstName(names[0]);
                    if (names.length > 1) {
                        newUser.setLastName(names[1]);
                    }
                }
            }
            newUser.setSingleAttribute("mobile", userInfo.get("mobile"));
            newUser.setSingleAttribute("customerNumber", userInfo.get("customerNumber"));
            newUser.setSingleAttribute("externalVerified", "true");
            newUser.setSingleAttribute("lastExternalVerification", String.valueOf(System.currentTimeMillis()));

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

            logger.infof("User updated in Keycloak successfully: %s", user.getUsername());
        } catch (Exception e) {
            logger.error("Error updating user in Keycloak", e);
        }
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