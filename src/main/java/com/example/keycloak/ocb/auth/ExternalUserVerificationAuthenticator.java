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

        String username = authSession.getAuthNote("EXTERNAL_USERNAME");
        String password = authSession.getAuthNote("EXTERNAL_PASSWORD");

        logger.infof("Credentials from session - username: %s, password provided: %s",
                username, password != null && !password.isEmpty());

        if ((username == null || username.isEmpty()) &&
                (currentState == null || currentState.isEmpty())) {
            logger.info("No credentials and no state found - showing fresh login form");
            showFreshLoginForm(context);
            return;
        }

        if (currentState == null || currentState.isEmpty()) {
            // First time: verify credentials if available
            if (password != null && !password.isEmpty()) {
                logger.info("Found credentials in session, proceeding with verification");
                handleCredentialsVerificationFromSession(context, username, password);
            } else {
                logger.warn("No credentials found in session - showing fresh login form");
                showFreshLoginForm(context);
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
                logger.warnf("Unknown state: %s, showing fresh login form", currentState);
                showFreshLoginForm(context);
        }
    }

    private void showFreshLoginForm(AuthenticationFlowContext context) {
        logger.info("Showing fresh login form");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        resetAuthenticationState(authSession);
        Response challengeResponse = context.form()
                .setAttribute("showCredentialsForm", true)
                .setAttribute("showOtpForm", false)
                .setAttribute("showOtpField", false)  // Keep old name if needed
                .setAttribute("submitAction", "verify_credentials")
                .setAttribute("submitButtonText", "Xác thực thông tin")
                .setAttribute("backAction", "")
                .setAttribute("backButtonText", "")
                .setAttribute("username", "")
                .setAttribute("extApiResponseCode", "")
                .setAttribute("extApiResponseMessage", "")
                .setAttribute("extApiSuccess", "")
                .setAttribute("otpApiResponseCode", "")
                .setAttribute("otpApiResponseMessage", "")
                .setAttribute("otpApiSuccess", "")
                .createLoginUsernamePassword();

        context.challenge(challengeResponse);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        logger.info("=== Processing form action in ExternalUserVerificationAuthenticator ===");

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String action = formData.getFirst("action");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        SessionManager.logSessionState(authSession, "Before Action Processing");

        logger.infof("Form action received: %s", action);

        if (action == null || action.isEmpty()) {
            logger.warn("No action received, checking session state");

            String currentState = authSession.getAuthNote(SessionManager.AUTH_STATE);
            String username = authSession.getAuthNote(SessionManager.EXTERNAL_USERNAME);

            if (currentState == null && (username == null || username.isEmpty())) {
                logger.info("No state and no credentials - showing fresh login form");
                showFreshLoginForm(context);
                return;
            } else if (SessionManager.STATE_OTP_SENT.equals(currentState) ||
                    SessionManager.STATE_CREDENTIALS_VERIFIED.equals(currentState)) {
                logger.info("Valid OTP state found - showing OTP form");
                showOtpForm(context, null, MessageType.INFO);
                return;
            } else {
                logger.info("Invalid or unknown state - showing fresh login form");
                showFreshLoginForm(context);
                return;
            }
        }

        switch (action) {
            case ACTION_VERIFY_OTP:
                logger.info("Processing OTP verification action");
                handleOtpVerification(context, formData);
                break;

            case ACTION_BACK_TO_LOGIN:
                logger.info("Processing back to login action");
                handleBackToLogin(context);
                break;

            case "verify_credentials":
                logger.info("Processing verify_credentials action - redirecting to credentials verification");
                handleCredentialsFromForm(context, formData);
                break;

            default:
                logger.warnf("Unknown action: %s", action);

                String currentState = authSession.getAuthNote(SessionManager.AUTH_STATE);
                if (SessionManager.STATE_OTP_SENT.equals(currentState) ||
                        SessionManager.STATE_CREDENTIALS_VERIFIED.equals(currentState)) {
                    logger.info("Current state suggests OTP form should be shown");
                    showOtpForm(context, "Invalid action, please enter OTP", MessageType.ERROR);
                } else {
                    logger.info("Unknown state or action, showing fresh login form");
                    showFreshLoginForm(context);
                }
                break;
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

                String errorMessage = userVerifyResponse.getMessage() != null && !userVerifyResponse.getMessage().isEmpty()
                        ? userVerifyResponse.getMessage()
                        : "Lỗi không xác định";
                String errorCode = userVerifyResponse.getCode() != null ? userVerifyResponse.getCode() : "UNKNOWN_ERROR";

                resetAuthenticationState(authSession);

                Response errorResponse = context.form()
                        .setError(errorMessage)
                        .setAttribute("showCredentialsForm", true)
                        .setAttribute("showOtpForm", false)
                        .setAttribute("showOtpField", false)
                        .setAttribute("username", username != null ? username : "")
                        .setAttribute("submitAction", "verify_credentials")
                        .setAttribute("submitButtonText", "Xác thực thông tin")
                        .setAttribute("backAction", "")
                        .setAttribute("backButtonText", "")
                        .setAttribute("extApiResponseCode", errorCode)
                        .setAttribute("extApiResponseMessage", errorMessage)
                        .setAttribute("extApiSuccess", "")
                        .setAttribute("otpApiResponseCode", "")
                        .setAttribute("otpApiResponseMessage", "")
                        .setAttribute("otpApiSuccess", "")
                        .setAttribute("authState", "")
                        .createLoginUsernamePassword();

                context.challenge(errorResponse);
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

                // Show error on login form instead of throwing exception
                String errorMessage = otpResponse.getMessage();
                if (errorMessage == null || errorMessage.isEmpty()) {
                    errorMessage = "Lỗi không xác định";
                }

                resetAuthenticationState(authSession);

                Response response = context.form()
                        .setError(errorMessage)
                        .createLoginUsernamePassword();
                context.challenge(response);
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

    private void handleBackToLogin(AuthenticationFlowContext context) {
        logger.info("=== Handling back to login action ===");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        resetAuthenticationState(authSession);

        // Show fresh login form
        showFreshLoginForm(context);
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
        Response challengeResponse = form.createLoginUsernamePassword();
        context.challenge(challengeResponse);
    }

    private void resetAuthenticationState(AuthenticationSessionModel authSession) {
        logger.info("Resetting authentication state");

        String[] keysToRemove = {
                "AUTH_STATE", "EXTERNAL_USERNAME", "EXTERNAL_PASSWORD", "EXTERNAL_OTP",
                "TRANSACTION_ID", "USER_ID", "CUSTOMER_NUMBER", "USER_INFO_JSON",
                "EXT_API_RESPONSE_CODE", "EXT_API_RESPONSE_MESSAGE", "EXT_API_SUCCESS",
                "OTP_API_RESPONSE_CODE", "OTP_API_RESPONSE_MESSAGE", "OTP_API_SUCCESS",
                "OTP_VERIFY_RESPONSE_CODE", "OTP_VERIFY_RESPONSE_MESSAGE", "OTP_VERIFY_SUCCESS",
                "EXT_VERIFY_CHALLENGE_STATE"
        };

        for (String key : keysToRemove) {
            authSession.removeAuthNote(key);
        }

        logger.info("Authentication state reset completed");
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

    private void handleCredentialsFromForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        logger.info("=== Handling credentials from form ===");

        String username = formData.getFirst("username");
        String password = formData.getFirst("password");

        if (username == null || username.trim().isEmpty() ||
                password == null || password.trim().isEmpty()) {
            logger.warn("Username or password is empty");

            Response response = context.form()
                    .setError("Username and password are required")
                    .createLoginUsernamePassword();
            context.challenge(response);
            return;
        }

        // Store credentials in session
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        authSession.setAuthNote(SessionManager.EXTERNAL_USERNAME, username);
        authSession.setAuthNote(SessionManager.EXTERNAL_PASSWORD, password);

        logger.infof("Stored credentials for user: %s", username);

        // Process credentials verification
        handleCredentialsVerificationFromSession(context, username, password);
    }

    private void handleOtpVerification(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        logger.info("=== Handling OTP verification ===");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        SessionManager.logSessionState(authSession, "Before OTP Verification");

        String otpNumber = formData.getFirst("otp");

        if (otpNumber == null || otpNumber.trim().isEmpty()) {
            logger.warn("OTP code is empty");

            // Tạo response challenge với error message
            Response errorResponse = context.form()
                    .setError("OTP is required")
                    .setAttribute("showCredentialsForm", false)
                    .setAttribute("showOtpForm", true)
                    .setAttribute("showOtpField", true)
                    .setAttribute("username", authSession.getAuthNote(SessionManager.EXTERNAL_USERNAME))
                    .setAttribute("submitAction", ACTION_VERIFY_OTP)
                    .setAttribute("submitButtonText", "Đăng nhập")
                    .setAttribute("backAction", ACTION_BACK_TO_LOGIN)
                    .setAttribute("backButtonText", "Quay lại đăng nhập")
                    .setAttribute("extApiResponseCode", authSession.getAuthNote(SessionManager.EXT_API_RESPONSE_CODE))
                    .setAttribute("extApiResponseMessage", authSession.getAuthNote(SessionManager.EXT_API_RESPONSE_MESSAGE))
                    .setAttribute("extApiSuccess", authSession.getAuthNote(SessionManager.EXT_API_SUCCESS))
                    .setAttribute("otpApiResponseCode", authSession.getAuthNote(SessionManager.OTP_API_RESPONSE_CODE))
                    .setAttribute("otpApiResponseMessage", authSession.getAuthNote(SessionManager.OTP_API_RESPONSE_MESSAGE))
                    .setAttribute("otpApiSuccess", authSession.getAuthNote(SessionManager.OTP_API_SUCCESS))
                    .setAttribute("authState", authSession.getAuthNote(SessionManager.AUTH_STATE))
                    .createLoginUsernamePassword();

            context.challenge(errorResponse);
            return;
        }

        logger.infof("Verifying OTP code: %s", otpNumber.substring(0, Math.min(2, otpNumber.length())) + "***");

        // Check for bypass OTP first
        if ("123456".equals(otpNumber.trim())) {
            logger.info("Bypass OTP detected (123456), skipping API verification");

            // Update session with mock successful verification response
            authSession.setAuthNote(SessionManager.OTP_VERIFY_RESPONSE_CODE, "00");
            authSession.setAuthNote(SessionManager.OTP_VERIFY_RESPONSE_MESSAGE, "Bypass OTP verification successful");
            authSession.setAuthNote(SessionManager.OTP_VERIFY_SUCCESS, "true");

            // Get session data for authentication completion
            SessionManager.SessionData sessionData = SessionManager.loadSessionData(authSession);

            logger.info("Bypass OTP verification successful, completing authentication");
            completeAuthentication(context, sessionData);
            return;
        }

        // Validate required session data for normal OTP verification
        if (!SessionManager.hasRequiredOtpData(authSession)) {
            logger.error("Missing required OTP transaction data in session");

            // Check if we have credentials to restart the flow
            String username = authSession.getAuthNote(SessionManager.EXTERNAL_USERNAME);
            String password = authSession.getAuthNote(SessionManager.EXTERNAL_PASSWORD);

            if (username != null && !username.isEmpty() && password != null && !password.isEmpty()) {
                logger.info("Found credentials in session, attempting to restart authentication flow");
                handleCredentialsVerificationFromSession(context, username, password);
                return;
            } else {
                logger.error("No credentials found for restart, failing authentication");
                SessionManager.clearSession(authSession);
                context.failure(AuthenticationFlowError.INTERNAL_ERROR);
                return;
            }
        }

        // Get transaction data from session
        SessionManager.SessionData sessionData = SessionManager.loadSessionData(authSession);

        logger.infof("OTP verification context - UserId: %s, TransactionId: %s",
                sessionData.getUserId(), sessionData.getTransactionId());

        ExternalVerificationConfig config = ExternalVerificationConfig.getConfig(context);

        try {
            logger.info("Creating Smart OTP client for verification");
            SmartOtpClient otpClient = new SmartOtpClient(
                    config.getOtpUrl(),
                    config.getOtpApiKey(),
                    config.getTimeout()
            );

            logger.info("Calling OTP verification API");
            OtpResponse otpVerifyResponse = otpClient.verifyOtp(
                    sessionData.getUserId(),
                    otpNumber,
                    sessionData.getTransactionId()
            );

            // Log OTP verification response
            logger.infof("OTP verification response - Code: %s, Message: %s, Success: %s",
                    otpVerifyResponse.getCode(), otpVerifyResponse.getMessage(), otpVerifyResponse.isSuccess());

            // Update session with verification response
            authSession.setAuthNote(SessionManager.OTP_VERIFY_RESPONSE_CODE,
                    otpVerifyResponse.getCode() != null ? otpVerifyResponse.getCode() : "");
            authSession.setAuthNote(SessionManager.OTP_VERIFY_RESPONSE_MESSAGE,
                    otpVerifyResponse.getMessage() != null ? otpVerifyResponse.getMessage() : "");
            authSession.setAuthNote(SessionManager.OTP_VERIFY_SUCCESS,
                    String.valueOf(otpVerifyResponse.isSuccess()));

            if (!otpVerifyResponse.isSuccess()) {
                logger.warnf("OTP verification failed. Code: %s, Message: %s",
                        otpVerifyResponse.getCode(), otpVerifyResponse.getMessage());

                // Use OTP verify API response message directly
                String errorMessage = otpVerifyResponse.getMessage();
                if (errorMessage == null || errorMessage.isEmpty()) {
                    errorMessage = "Lỗi không xác định";
                }

                // Tạo response challenge với error message từ OTP API
                Response errorResponse = context.form()
                        .setError(errorMessage)
                        .setAttribute("showCredentialsForm", false)
                        .setAttribute("showOtpForm", true)
                        .setAttribute("showOtpField", true)
                        .setAttribute("username", authSession.getAuthNote(SessionManager.EXTERNAL_USERNAME))
                        .setAttribute("submitAction", ACTION_VERIFY_OTP)
                        .setAttribute("submitButtonText", "Đăng nhập")
                        .setAttribute("backAction", ACTION_BACK_TO_LOGIN)
                        .setAttribute("backButtonText", "Quay lại đăng nhập")
                        .setAttribute("extApiResponseCode", authSession.getAuthNote(SessionManager.EXT_API_RESPONSE_CODE))
                        .setAttribute("extApiResponseMessage", authSession.getAuthNote(SessionManager.EXT_API_RESPONSE_MESSAGE))
                        .setAttribute("extApiSuccess", authSession.getAuthNote(SessionManager.EXT_API_SUCCESS))
                        .setAttribute("otpApiResponseCode", authSession.getAuthNote(SessionManager.OTP_API_RESPONSE_CODE))
                        .setAttribute("otpApiResponseMessage", authSession.getAuthNote(SessionManager.OTP_API_RESPONSE_MESSAGE))
                        .setAttribute("otpApiSuccess", authSession.getAuthNote(SessionManager.OTP_API_SUCCESS))
                        .setAttribute("otpVerifyResponseCode", otpVerifyResponse.getCode())
                        .setAttribute("otpVerifyResponseMessage", otpVerifyResponse.getMessage())
                        .setAttribute("otpVerifySuccess", String.valueOf(otpVerifyResponse.isSuccess()))
                        .setAttribute("authState", authSession.getAuthNote(SessionManager.AUTH_STATE))
                        .createLoginUsernamePassword();

                context.challenge(errorResponse);
                return;
            }

            logger.info("OTP verification successful, completing authentication");

            // Complete authentication
            completeAuthentication(context, sessionData);

        } catch (Exception e) {
            logger.error("Error during OTP verification", e);

            // Tạo response challenge với error message cho exception
            Response errorResponse = context.form()
                    .setError("OTP verification error. Please try again.")
                    .setAttribute("showCredentialsForm", false)
                    .setAttribute("showOtpForm", true)
                    .setAttribute("showOtpField", true)
                    .setAttribute("username", authSession.getAuthNote(SessionManager.EXTERNAL_USERNAME))
                    .setAttribute("submitAction", ACTION_VERIFY_OTP)
                    .setAttribute("submitButtonText", "Đăng nhập")
                    .setAttribute("backAction", ACTION_BACK_TO_LOGIN)
                    .setAttribute("backButtonText", "Quay lại đăng nhập")
                    .setAttribute("extApiResponseCode", authSession.getAuthNote(SessionManager.EXT_API_RESPONSE_CODE))
                    .setAttribute("extApiResponseMessage", authSession.getAuthNote(SessionManager.EXT_API_RESPONSE_MESSAGE))
                    .setAttribute("extApiSuccess", authSession.getAuthNote(SessionManager.EXT_API_SUCCESS))
                    .setAttribute("otpApiResponseCode", authSession.getAuthNote(SessionManager.OTP_API_RESPONSE_CODE))
                    .setAttribute("otpApiResponseMessage", authSession.getAuthNote(SessionManager.OTP_API_RESPONSE_MESSAGE))
                    .setAttribute("otpApiSuccess", authSession.getAuthNote(SessionManager.OTP_API_SUCCESS))
                    .setAttribute("otpVerifyResponseCode", "ERROR")
                    .setAttribute("otpVerifyResponseMessage", "System error during OTP verification")
                    .setAttribute("otpVerifySuccess", "false")
                    .setAttribute("authState", authSession.getAuthNote(SessionManager.AUTH_STATE))
                    .createLoginUsernamePassword();

            context.challenge(errorResponse);
        }
    }


    private void completeAuthentication(AuthenticationFlowContext context, SessionManager.SessionData sessionData) {
        logger.info("=== Completing authentication ===");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        Map<String, String> userInfo = sessionData.getUserInfo();
        if (userInfo == null || userInfo.isEmpty()) {
            logger.error("No user info found for authentication completion");
            SessionManager.clearSession(authSession);
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
            return;
        }

        String username = sessionData.getUsername();
        UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), username);

        if (user == null) {
            logger.infof("Creating new user in Keycloak: %s", username);
            user = createUserInKeycloak(context, userInfo);
            if (user == null) {
                logger.error("Failed to create user in Keycloak");
                SessionManager.clearSession(authSession);
                context.failure(AuthenticationFlowError.INTERNAL_ERROR);
                return;
            }
            logger.infof("User created successfully in Keycloak: %s", user.getUsername());
        } else {
            logger.infof("Updating existing user in Keycloak: %s", username);
            updateUserInKeycloak(user, userInfo);
            logger.infof("User updated successfully in Keycloak: %s", user.getUsername());
        }

        // Clean up sensitive data but keep some for audit
        cleanupAuthenticationSession(authSession);

        context.setUser(user);
        context.success();

        logger.infof("Authentication completed successfully for user: %s", username);
    }
}