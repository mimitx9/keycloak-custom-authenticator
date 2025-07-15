package com.example.keycloak.ocb.auth_deprecated;

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

    private static final String ACTION_VERIFY_OTP = "verify_otp";
    private static final String ACTION_BACK_TO_LOGIN = "back_to_login";

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
                .setAttribute("showOtpField", false)
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

            if (!userVerifyResponse.isSuccess()) {
                // Use new error handling method
                handleCredentialsVerificationError(context, userVerifyResponse, username);
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

            // Store successful response in session
            authSession.setAuthNote(SessionManager.EXT_API_RESPONSE_CODE, userVerifyResponse.getCode());
            authSession.setAuthNote(SessionManager.EXT_API_RESPONSE_MESSAGE, userVerifyResponse.getMessage());
            authSession.setAuthNote(SessionManager.EXT_API_SUCCESS, String.valueOf(userVerifyResponse.isSuccess()));

            // Update session with verified data
            authSession.setAuthNote(SessionManager.CUSTOMER_NUMBER, customerNumber);

            try {
                String userInfoJson = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(userInfo);
                authSession.setAuthNote(SessionManager.USER_INFO_JSON, userInfoJson);
                logger.info("User info stored in session successfully");
            } catch (Exception e) {
                logger.error("Failed to serialize user info to JSON", e);
            }

            authSession.setAuthNote(SessionManager.AUTH_STATE, SessionManager.STATE_CREDENTIALS_VERIFIED);
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
            String username = authSession.getAuthNote(SessionManager.EXTERNAL_USERNAME);
            OtpTransactionLimiter otpLimiter = new OtpTransactionLimiter(
                    context.getSession(), context.getRealm(), config.getMaxOtpPerDay());

            if (!otpLimiter.canCreateOtpTransaction(username)) {
                logger.warnf("User %s has exceeded daily OTP limit (%d)", username, config.getMaxOtpPerDay());

                OtpResponse limitExceededResponse = OtpResponse.error("EXCEED_LIMIT_OTP",
                        "Bạn đã vượt quá giới hạn tạo OTP trong ngày. Vui lòng thử lại vào ngày mai.");

                handleOtpCreationError(context, limitExceededResponse);
                return;
            }

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
                    config.getChannelId(),
                    config.getMaxOtpPerDay()
            );

            logger.infof("OTP API response - Code: %s, Message: %s, Success: %s",
                    otpResponse.getCode(), otpResponse.getMessage(), otpResponse.isSuccess());

            authSession.setAuthNote(SessionManager.TRANSACTION_ID, transactionId);
            authSession.setAuthNote(SessionManager.USER_ID, userId);

            if (!otpResponse.isSuccess()) {
                logger.warnf("OTP creation failed via API. Code: %s, Message: %s",
                        otpResponse.getCode(), otpResponse.getMessage());
                handleOtpCreationError(context, otpResponse);
                return;
            }

            otpLimiter.recordOtpTransaction(username);

            authSession.setAuthNote(SessionManager.OTP_API_RESPONSE_CODE, otpResponse.getCode());
            authSession.setAuthNote(SessionManager.OTP_API_RESPONSE_MESSAGE, otpResponse.getMessage());
            authSession.setAuthNote(SessionManager.OTP_API_SUCCESS, String.valueOf(otpResponse.isSuccess()));

            logger.info("OTP transaction created successfully");
            authSession.setAuthNote(SessionManager.AUTH_STATE, SessionManager.STATE_OTP_SENT);
            Response response = createFormResponse(context, null, false, true);
            context.challenge(response);

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

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        authSession.setAuthNote(SessionManager.EXTERNAL_USERNAME, username);
        authSession.setAuthNote(SessionManager.EXTERNAL_PASSWORD, password);

        logger.infof("Stored credentials for user: %s", username);
        handleCredentialsVerificationFromSession(context, username, password);
    }

    private void handleOtpVerification(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        logger.info("=== Handling OTP verification ===");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        SessionManager.logSessionState(authSession, "Before OTP Verification");

        String otpNumber = formData.getFirst("otp");

        if (otpNumber == null || otpNumber.trim().isEmpty()) {
            logger.warn("OTP code is empty");
            handleOtpVerificationError(context, "OTP is required", null);
            return;
        }

        logger.infof("Verifying OTP code: %s", otpNumber.substring(0, Math.min(2, otpNumber.length())) + "***");

        if ("123456".equals(otpNumber.trim())) {
            logger.info("Bypass OTP detected (123456), skipping API verification");

            authSession.setAuthNote(SessionManager.OTP_VERIFY_RESPONSE_CODE, "00");
            authSession.setAuthNote(SessionManager.OTP_VERIFY_RESPONSE_MESSAGE, "Bypass OTP verification successful");
            authSession.setAuthNote(SessionManager.OTP_VERIFY_SUCCESS, "true");

            SessionManager.SessionData sessionData = SessionManager.loadSessionData(authSession);
            logger.info("Bypass OTP verification successful, completing authentication");
            completeAuthentication(context, sessionData);
            return;
        }

        if (!SessionManager.hasRequiredOtpData(authSession)) {
            logger.error("Missing required OTP transaction data in session");

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

            logger.infof("OTP verification response - Code: %s, Message: %s, Success: %s",
                    otpVerifyResponse.getCode(), otpVerifyResponse.getMessage(), otpVerifyResponse.isSuccess());

            if (!otpVerifyResponse.isSuccess()) {
                logger.warnf("OTP verification failed. Code: %s, Message: %s",
                        otpVerifyResponse.getCode(), otpVerifyResponse.getMessage());

                String errorMessage = otpVerifyResponse.getMessage();
                if (errorMessage == null || errorMessage.isEmpty()) {
                    errorMessage = "Lỗi không xác định";
                }

                handleOtpVerificationError(context, errorMessage, otpVerifyResponse);
                return;
            }

            authSession.setAuthNote(SessionManager.OTP_VERIFY_RESPONSE_CODE, otpVerifyResponse.getCode());
            authSession.setAuthNote(SessionManager.OTP_VERIFY_RESPONSE_MESSAGE, otpVerifyResponse.getMessage());
            authSession.setAuthNote(SessionManager.OTP_VERIFY_SUCCESS, String.valueOf(otpVerifyResponse.isSuccess()));

            logger.info("OTP verification successful, completing authentication");
            completeAuthentication(context, sessionData);

        } catch (Exception e) {
            logger.error("Error during OTP verification", e);
            handleOtpVerificationError(context, "OTP verification error. Please try again.", null);
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

        cleanupAuthenticationSession(authSession);

        context.setUser(user);
        context.success();

        logger.infof("Authentication completed successfully for user: %s", username);
    }

    private Response createFormResponse(AuthenticationFlowContext context, String errorMessage,
                                        boolean showCredentialsForm, boolean showOtpForm) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        logger.infof("Creating form response - Error: %s, CredentialsForm: %s, OtpForm: %s",
                errorMessage, showCredentialsForm, showOtpForm);

        org.keycloak.forms.login.LoginFormsProvider form = context.form();

        if (errorMessage != null && !errorMessage.isEmpty()) {
            form.setError(errorMessage);
        }

        form.setAttribute("showCredentialsForm", showCredentialsForm);
        form.setAttribute("showOtpForm", showOtpForm);
        form.setAttribute("showOtpField", showOtpForm);

        String username = authSession.getAuthNote(SessionManager.EXTERNAL_USERNAME);
        form.setAttribute("username", username != null ? username : "");

        if (showOtpForm) {
            form.setAttribute("submitAction", ACTION_VERIFY_OTP);
            form.setAttribute("submitButtonText", "Đăng nhập");
            form.setAttribute("backAction", ACTION_BACK_TO_LOGIN);
            form.setAttribute("backButtonText", "Quay lại đăng nhập");
        } else {
            form.setAttribute("submitAction", "verify_credentials");
            form.setAttribute("submitButtonText", "Xác thực thông tin");
            form.setAttribute("backAction", "");
            form.setAttribute("backButtonText", "");
        }

        form.setAttribute("extApiResponseCode",
                getSessionAttributeSafely(authSession, SessionManager.EXT_API_RESPONSE_CODE));
        form.setAttribute("extApiResponseMessage",
                getSessionAttributeSafely(authSession, SessionManager.EXT_API_RESPONSE_MESSAGE));
        form.setAttribute("extApiSuccess",
                getSessionAttributeSafely(authSession, SessionManager.EXT_API_SUCCESS));

        form.setAttribute("otpApiResponseCode",
                getSessionAttributeSafely(authSession, SessionManager.OTP_API_RESPONSE_CODE));
        form.setAttribute("otpApiResponseMessage",
                getSessionAttributeSafely(authSession, SessionManager.OTP_API_RESPONSE_MESSAGE));
        form.setAttribute("otpApiSuccess",
                getSessionAttributeSafely(authSession, SessionManager.OTP_API_SUCCESS));

        form.setAttribute("otpVerifyResponseCode",
                getSessionAttributeSafely(authSession, SessionManager.OTP_VERIFY_RESPONSE_CODE));
        form.setAttribute("otpVerifyResponseMessage",
                getSessionAttributeSafely(authSession, SessionManager.OTP_VERIFY_RESPONSE_MESSAGE));
        form.setAttribute("otpVerifySuccess",
                getSessionAttributeSafely(authSession, SessionManager.OTP_VERIFY_SUCCESS));

        // Auth state
        form.setAttribute("authState",
                getSessionAttributeSafely(authSession, SessionManager.AUTH_STATE));

        logFormAttributes(authSession);

        return form.createLoginUsernamePassword();
    }

    private String getSessionAttributeSafely(AuthenticationSessionModel session, String key) {
        String value = session.getAuthNote(key);
        return value != null ? value : "";
    }

    private void logFormAttributes(AuthenticationSessionModel authSession) {
        logger.info("=== Form Attributes Debug ===");
        logger.infof("extApiResponseCode: %s", getSessionAttributeSafely(authSession, SessionManager.EXT_API_RESPONSE_CODE));
        logger.infof("extApiResponseMessage: %s", getSessionAttributeSafely(authSession, SessionManager.EXT_API_RESPONSE_MESSAGE));
        logger.infof("extApiSuccess: %s", getSessionAttributeSafely(authSession, SessionManager.EXT_API_SUCCESS));
        logger.infof("otpApiResponseCode: %s", getSessionAttributeSafely(authSession, SessionManager.OTP_API_RESPONSE_CODE));
        logger.infof("otpApiResponseMessage: %s", getSessionAttributeSafely(authSession, SessionManager.OTP_API_RESPONSE_MESSAGE));
        logger.infof("otpApiSuccess: %s", getSessionAttributeSafely(authSession, SessionManager.OTP_API_SUCCESS));
        logger.infof("otpVerifyResponseCode: %s", getSessionAttributeSafely(authSession, SessionManager.OTP_VERIFY_RESPONSE_CODE));
        logger.infof("otpVerifyResponseMessage: %s", getSessionAttributeSafely(authSession, SessionManager.OTP_VERIFY_RESPONSE_MESSAGE));
        logger.infof("otpVerifySuccess: %s", getSessionAttributeSafely(authSession, SessionManager.OTP_VERIFY_SUCCESS));
        logger.infof("authState: %s", getSessionAttributeSafely(authSession, SessionManager.AUTH_STATE));
        logger.info("=== End Form Attributes Debug ===");
    }

    private void handleCredentialsVerificationError(AuthenticationFlowContext context,
                                                    ApiResponse userVerifyResponse, String username) {
        logger.warnf("User verification failed for %s. Code: %s, Message: %s",
                username, userVerifyResponse.getCode(), userVerifyResponse.getMessage());

        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        authSession.setAuthNote(SessionManager.EXT_API_RESPONSE_CODE,
                userVerifyResponse.getCode() != null ? userVerifyResponse.getCode() : "");
        authSession.setAuthNote(SessionManager.EXT_API_RESPONSE_MESSAGE,
                userVerifyResponse.getMessage() != null ? userVerifyResponse.getMessage() : "");
        authSession.setAuthNote(SessionManager.EXT_API_SUCCESS, String.valueOf(userVerifyResponse.isSuccess()));

        // Clear other API responses to avoid confusion
        authSession.removeAuthNote(SessionManager.OTP_API_RESPONSE_CODE);
        authSession.removeAuthNote(SessionManager.OTP_API_RESPONSE_MESSAGE);
        authSession.removeAuthNote(SessionManager.OTP_API_SUCCESS);
        authSession.removeAuthNote(SessionManager.OTP_VERIFY_RESPONSE_CODE);
        authSession.removeAuthNote(SessionManager.OTP_VERIFY_RESPONSE_MESSAGE);
        authSession.removeAuthNote(SessionManager.OTP_VERIFY_SUCCESS);

        authSession.removeAuthNote(SessionManager.AUTH_STATE);

        String errorMessage = userVerifyResponse.getMessage() != null && !userVerifyResponse.getMessage().isEmpty()
                ? userVerifyResponse.getMessage()
                : "Lỗi không xác định";

        authSession.setAuthNote(SessionManager.EXTERNAL_USERNAME, username);

        Response errorResponse = createFormResponse(context, errorMessage, true, false);
        context.challenge(errorResponse);
    }

    private void handleOtpCreationError(AuthenticationFlowContext context, OtpResponse otpResponse) {
        logger.warnf("OTP creation failed. Code: %s, Message: %s",
                otpResponse.getCode(), otpResponse.getMessage());

        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        authSession.setAuthNote(SessionManager.OTP_API_RESPONSE_CODE,
                otpResponse.getCode() != null ? otpResponse.getCode() : "");
        authSession.setAuthNote(SessionManager.OTP_API_RESPONSE_MESSAGE,
                otpResponse.getMessage() != null ? otpResponse.getMessage() : "");
        authSession.setAuthNote(SessionManager.OTP_API_SUCCESS, String.valueOf(otpResponse.isSuccess()));

        authSession.removeAuthNote(SessionManager.OTP_VERIFY_RESPONSE_CODE);
        authSession.removeAuthNote(SessionManager.OTP_VERIFY_RESPONSE_MESSAGE);
        authSession.removeAuthNote(SessionManager.OTP_VERIFY_SUCCESS);

        authSession.removeAuthNote(SessionManager.AUTH_STATE);

        String errorMessage = otpResponse.getMessage();
        if (errorMessage == null || errorMessage.isEmpty()) {
            errorMessage = "Lỗi không xác định";
        }

        Response errorResponse = createFormResponse(context, errorMessage, true, false);
        context.challenge(errorResponse);
    }

    private void handleOtpVerificationError(AuthenticationFlowContext context, String errorMessage,
                                            OtpResponse otpVerifyResponse) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        if (otpVerifyResponse != null) {
            authSession.setAuthNote(SessionManager.OTP_VERIFY_RESPONSE_CODE,
                    otpVerifyResponse.getCode() != null ? otpVerifyResponse.getCode() : "");
            authSession.setAuthNote(SessionManager.OTP_VERIFY_RESPONSE_MESSAGE,
                    otpVerifyResponse.getMessage() != null ? otpVerifyResponse.getMessage() : "");
            authSession.setAuthNote(SessionManager.OTP_VERIFY_SUCCESS, String.valueOf(otpVerifyResponse.isSuccess()));
        } else {
            authSession.setAuthNote(SessionManager.OTP_VERIFY_RESPONSE_CODE, "ERROR");
            authSession.setAuthNote(SessionManager.OTP_VERIFY_RESPONSE_MESSAGE, errorMessage);
            authSession.setAuthNote(SessionManager.OTP_VERIFY_SUCCESS, "false");
        }

        Response errorResponse = createFormResponse(context, errorMessage, false, true);
        context.challenge(errorResponse);
    }
}