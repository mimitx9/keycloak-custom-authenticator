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
import java.util.UUID;

public class ExternalUserVerificationAuthenticator implements Authenticator {
    private static final Logger logger = Logger.getLogger(ExternalUserVerificationAuthenticator.class);

    private static final String ACTION_VERIFY_CREDENTIALS = "verify_credentials";
    private static final String ACTION_VERIFY_OTP = "verify_otp";
    private static final String ACTION_BACK_TO_LOGIN = "back_to_login";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        logger.info("=== Starting authentication process ===");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String currentState = authSession.getAuthNote("AUTH_STATE");

        logger.infof("Current authentication state: %s", currentState);

        if (currentState == null || currentState.isEmpty()) {
            logger.info("No current state found, showing initial login form");
            showInitialLoginForm(context);
            return;
        }

        switch (currentState) {
            case "CREDENTIALS_VERIFIED":
                logger.info("Credentials already verified, showing OTP form");
                showOtpForm(context, null);
                break;
            case "OTP_SENT":
                logger.info("OTP already sent, showing OTP form");
                showOtpForm(context, null);
                break;
            default:
                logger.warnf("Unknown state: %s, resetting to initial form", currentState);
                resetAuthenticationState(authSession);
                showInitialLoginForm(context);
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        logger.info("=== Processing form action ===");

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String action = formData.getFirst("action");

        logger.infof("Form action received: %s", action);

        formData.forEach((key, values) -> {
            if (!"password".equals(key) && !"otp".equals(key)) {
                logger.infof("Form parameter - %s: %s", key, values);
            } else {
                logger.infof("Form parameter - %s: [REDACTED]", key);
            }
        });

        if (ACTION_VERIFY_CREDENTIALS.equals(action)) {
            handleCredentialsVerification(context, formData);
        } else if (ACTION_VERIFY_OTP.equals(action)) {
            handleOtpVerification(context, formData);
        } else if (ACTION_BACK_TO_LOGIN.equals(action)) {
            handleBackToLogin(context);
        } else {
            logger.warnf("Unknown action: %s", action);
            showInitialLoginForm(context);
        }
    }

    private void handleCredentialsVerification(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        logger.info("=== Handling credentials verification ===");

        String username = formData.getFirst("username");
        String password = formData.getFirst("password");

        logger.infof("Verifying credentials for username: %s", username);

        if (username == null || username.trim().isEmpty()) {
            logger.warn("Username is empty");
            showInitialLoginForm(context, "Username is required");
            return;
        }

        if (password == null || password.trim().isEmpty()) {
            logger.warn("Password is empty");
            showInitialLoginForm(context, "Password is required");
            return;
        }

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        ExternalVerificationConfig config = ExternalVerificationConfig.getConfig(context);

        if (!config.isValid()) {
            logger.error("External verification config is invalid");
            showInitialLoginForm(context, "Configuration error");
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

                String errorMessage = userVerifyResponse.getMessage();
                if (errorMessage == null || errorMessage.isEmpty()) {
                    errorMessage = "Code: " + userVerifyResponse.getCode();
                }

                showInitialLoginForm(context, errorMessage);
                return;
            }

            logger.info("User verification successful, extracting user info");
            Map<String, String> userInfo = userVerifyResponse.getUserInfo();

            if (userInfo == null || userInfo.isEmpty()) {
                logger.error("No user info returned from successful API call");
                showInitialLoginForm(context, "No user data in successful response");
                return;
            }

            String customerNumber = userInfo.get("customerNumber");
            if (customerNumber == null || customerNumber.isEmpty()) {
                logger.error("No customerNumber found in user verification response");
                showInitialLoginForm(context, "No customerNumber in response");
                return;
            }

            logger.infof("User info extracted - CustomerNumber: %s, Email: %s, Mobile: %s",
                    customerNumber, userInfo.get("email"), userInfo.get("mobile"));

            authSession.setAuthNote("EXTERNAL_USERNAME", username);
            authSession.setAuthNote("EXTERNAL_PASSWORD", password);
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
            showInitialLoginForm(context, "Unexpected error: " + e.getMessage());
        }
    }

    private void createOtpTransaction(AuthenticationFlowContext context, Map<String, String> userInfo, ExternalVerificationConfig config) {
        logger.info("=== Creating OTP transaction ===");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String customerNumber = userInfo.get("customerNumber");

        if (!config.isOtpConfigValid()) {
            logger.error("OTP configuration is invalid");
            showInitialLoginForm(context, "OTP configuration invalid");
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

                // Use OTP API response message directly
                String errorMessage = otpResponse.getMessage();
                if (errorMessage == null || errorMessage.isEmpty()) {
                    errorMessage = "OTP Error Code: " + otpResponse.getCode();
                }

                // Reset to initial state on OTP creation failure
                resetAuthenticationState(authSession);
                showInitialLoginForm(context, errorMessage);
                return;
            }

            logger.info("OTP transaction created successfully");
            authSession.setAuthNote("AUTH_STATE", "OTP_SENT");

            // Use OTP API success message directly
            String successMessage = otpResponse.getMessage();
            if (successMessage == null || successMessage.isEmpty()) {
                successMessage = "OTP sent successfully";
            }

            showOtpForm(context, successMessage);

        } catch (Exception e) {
            logger.error("Error creating OTP transaction", e);
            resetAuthenticationState(authSession);
            showInitialLoginForm(context, "OTP creation error: " + e.getMessage());
        }
    }

    private void handleOtpVerification(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        logger.info("=== Handling OTP verification ===");

        String otpNumber = formData.getFirst("otp");

        if (otpNumber == null || otpNumber.trim().isEmpty()) {
            logger.warn("OTP code is empty");
            showOtpForm(context, "OTP is required");
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
            showInitialLoginForm(context, "Session expired");
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

                showOtpForm(context, errorMessage);
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
                showInitialLoginForm(context, "Session data lost");
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
                    showInitialLoginForm(context, "Failed to create user account");
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
            showOtpForm(context, "OTP verification error: " + e.getMessage());
        }
    }

    private void handleBackToLogin(AuthenticationFlowContext context) {
        logger.info("=== Handling back to login action ===");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        resetAuthenticationState(authSession);

        showInitialLoginForm(context);
    }

    private void showInitialLoginForm(AuthenticationFlowContext context) {
        showInitialLoginForm(context, null);
    }

    private void showInitialLoginForm(AuthenticationFlowContext context, String errorMessage) {
        logger.info("Showing initial login form");

        org.keycloak.forms.login.LoginFormsProvider form = context.form()
                .setAttribute("showCredentialsForm", true)
                .setAttribute("showOtpForm", false)
                .setAttribute("submitAction", ACTION_VERIFY_CREDENTIALS)
                .setAttribute("submitButtonText", "Xác thực thông tin");

        if (errorMessage != null && !errorMessage.isEmpty()) {
            logger.infof("Showing login form with error: %s", errorMessage);
            form.setError(errorMessage);
        }
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        addDebugAttributes(form, authSession);

        Response challengeResponse = form.createLoginUsernamePassword();
        context.challenge(challengeResponse);
    }

    private void showOtpForm(AuthenticationFlowContext context, String message) {
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
            if (message.contains("lỗi") || message.contains("không đúng") || message.contains("thất bại")) {
                logger.infof("Showing OTP form with error: %s", message);
                form.setError(message);
            } else {
                logger.infof("Showing OTP form with info: %s", message);
                form.setInfo(message);
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

            // Update custom attributes
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