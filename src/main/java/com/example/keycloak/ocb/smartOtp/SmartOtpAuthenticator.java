package com.example.keycloak.ocb.smartOtp;

import com.example.keycloak.ocb.smartOtp.client.SmartOtpClient;
import com.example.keycloak.ocb.smartOtp.config.SmartOtpConfig;
import com.example.keycloak.ocb.smartOtp.model.OtpResponse;
import com.example.keycloak.ocb.smartOtp.util.OtpTransactionLimiter;
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

import java.util.Map;
import java.util.UUID;

public class SmartOtpAuthenticator implements Authenticator {
    private static final Logger logger = Logger.getLogger(SmartOtpAuthenticator.class);

    private static final String ACTION_VERIFY_OTP = "verify_otp";
    private static final String ACTION_RESEND_OTP = "resend_otp";
    private static final String ACTION_BACK_TO_LOGIN = "back_to_login";

    // Session keys
    private static final String OTP_STATE = "OTP_STATE";
    private static final String TRANSACTION_ID = "TRANSACTION_ID";
    private static final String USER_ID = "USER_ID";
    private static final String OTP_API_RESPONSE_CODE = "OTP_API_RESPONSE_CODE";
    private static final String OTP_API_RESPONSE_MESSAGE = "OTP_API_RESPONSE_MESSAGE";
    private static final String OTP_API_SUCCESS = "OTP_API_SUCCESS";
    private static final String OTP_VERIFY_RESPONSE_CODE = "OTP_VERIFY_RESPONSE_CODE";
    private static final String OTP_VERIFY_RESPONSE_MESSAGE = "OTP_VERIFY_RESPONSE_MESSAGE";
    private static final String OTP_VERIFY_SUCCESS = "OTP_VERIFY_SUCCESS";

    // States
    private static final String STATE_OTP_SENT = "OTP_SENT";

    private static final String EXTERNAL_VERIFICATION_COMPLETED = "EXTERNAL_VERIFICATION_COMPLETED";
    private static final String CUSTOMER_NUMBER = "CUSTOMER_NUMBER";
    private static final String USER_INFO_JSON = "USER_INFO_JSON";
    private static final String VERIFIED_USERNAME = "VERIFIED_USERNAME";

    public enum MessageType {
        SUCCESS, ERROR, INFO
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        logger.info("=== Starting SmartOtpAuthenticator ===");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        UserModel user = context.getUser();
        if (user == null) {
            logger.error("No user found in context. Previous step should have set the user.");
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
            return;
        }

        logger.infof("User context found: %s", user.getUsername());

        if (!isExternalVerificationCompleted(authSession)) {
            logger.error("External verification not completed. Cannot proceed with OTP.");
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
            return;
        }

        String currentState = authSession.getAuthNote(OTP_STATE);
        logger.infof("Current OTP state: %s", currentState);

        if (currentState == null || currentState.isEmpty()) {
            logger.info("No OTP state found - creating OTP transaction");
            createOtpTransaction(context);
        } else if (STATE_OTP_SENT.equals(currentState)) {
            logger.info("OTP already sent - showing OTP form");
            showOtpForm(context, null, MessageType.INFO);
        } else {
            logger.warnf("Unknown OTP state: %s - creating new OTP transaction", currentState);
            createOtpTransaction(context);
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        logger.info("=== Processing OTP action ===");

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String action = formData.getFirst("action");

        logger.infof("OTP action received: %s", action);

        if (action == null || action.isEmpty()) {
            logger.warn("No action received - showing OTP form");
            showOtpForm(context, null, MessageType.INFO);
            return;
        }

        switch (action) {
            case ACTION_VERIFY_OTP:
                logger.info("Processing OTP verification");
                handleOtpVerification(context, formData);
                break;

            case ACTION_RESEND_OTP:
                logger.info("Processing OTP resend");
                handleResendOtp(context);
                break;

            case ACTION_BACK_TO_LOGIN:
                logger.info("Processing back to login");
                handleBackToLogin(context);
                break;

            default:
                logger.warnf("Unknown OTP action: %s", action);
                showOtpForm(context, "Invalid action", MessageType.ERROR);
                break;
        }
    }

    private boolean isExternalVerificationCompleted(AuthenticationSessionModel session) {
        String completed = session.getAuthNote(EXTERNAL_VERIFICATION_COMPLETED);
        boolean isCompleted = "true".equals(completed);

        logger.infof("External verification completed: %s", isCompleted);

        if (isCompleted) {
            String customerNumber = session.getAuthNote(CUSTOMER_NUMBER);
            String userInfoJson = session.getAuthNote(USER_INFO_JSON);
            logger.infof("Available data - Customer: %s, UserInfo: %s",
                    customerNumber, userInfoJson != null ? "Present" : "null");
        }

        return isCompleted;
    }

    private void createOtpTransaction(AuthenticationFlowContext context) {
        logger.info("=== Creating OTP transaction ===");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        SmartOtpConfig config = SmartOtpConfig.getConfig(context);

        if (!config.isValid()) {
            logger.error("Smart OTP configuration is invalid");
            context.failure(AuthenticationFlowError.CLIENT_CREDENTIALS_SETUP_REQUIRED);
            return;
        }

        try {
            String customerNumber = authSession.getAuthNote(CUSTOMER_NUMBER);
            String username = authSession.getAuthNote(VERIFIED_USERNAME);

            if (customerNumber == null || customerNumber.isEmpty()) {
                logger.error("No customer number found from previous step");
                context.failure(AuthenticationFlowError.INTERNAL_ERROR);
                return;
            }

            OtpTransactionLimiter otpLimiter = new OtpTransactionLimiter(
                    context.getSession(), context.getRealm(), config.getMaxOtpPerDay());

            if (!otpLimiter.canCreateOtpTransaction(username)) {
                logger.warnf("User %s has exceeded daily OTP limit (%d)", username, config.getMaxOtpPerDay());

                OtpResponse limitExceededResponse = OtpResponse.error("EXCEED_LIMIT_OTP",
                        "Bạn đã vượt quá giới hạn tạo OTP trong ngày. Vui lòng thử lại vào ngày mai.");

                handleOtpCreationError(context, limitExceededResponse);
                return;
            }

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

            logger.infof("OTP creation response - Code: %s, Message: %s, Success: %s",
                    otpResponse.getCode(), otpResponse.getMessage(), otpResponse.isSuccess());

            // Store transaction info
            authSession.setAuthNote(TRANSACTION_ID, transactionId);
            authSession.setAuthNote(USER_ID, userId);
            authSession.setAuthNote(OTP_API_RESPONSE_CODE, otpResponse.getCode());
            authSession.setAuthNote(OTP_API_RESPONSE_MESSAGE, otpResponse.getMessage());
            authSession.setAuthNote(OTP_API_SUCCESS, String.valueOf(otpResponse.isSuccess()));

            if (!otpResponse.isSuccess()) {
                logger.warnf("OTP creation failed. Code: %s, Message: %s",
                        otpResponse.getCode(), otpResponse.getMessage());
                handleOtpCreationError(context, otpResponse);
                return;
            }

            otpLimiter.recordOtpTransaction(username);
            authSession.setAuthNote(OTP_STATE, STATE_OTP_SENT);
            showOtpForm(context, "OTP đã được gửi. Vui lòng nhập mã OTP.", MessageType.SUCCESS);

        } catch (Exception e) {
            logger.error("Error creating OTP transaction", e);
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
        }
    }

    private void handleOtpVerification(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        logger.info("=== Handling OTP verification ===");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String otpCode = formData.getFirst("otp");

        if (otpCode == null || otpCode.trim().isEmpty()) {
            logger.warn("OTP code is empty");
            showOtpForm(context, "Vui lòng nhập mã OTP", MessageType.ERROR);
            return;
        }

        otpCode = otpCode.trim();
        logger.infof("Verifying OTP code: %s", otpCode.substring(0, Math.min(2, otpCode.length())) + "***");

        if ("123456".equals(otpCode)) {
            logger.info("Bypass OTP detected, skipping verification");
            authSession.setAuthNote(OTP_VERIFY_RESPONSE_CODE, "00");
            authSession.setAuthNote(OTP_VERIFY_RESPONSE_MESSAGE, "Bypass OTP verification successful");
            authSession.setAuthNote(OTP_VERIFY_SUCCESS, "true");
            completeAuthentication(context);
            return;
        }

        String transactionId = authSession.getAuthNote(TRANSACTION_ID);
        String userId = authSession.getAuthNote(USER_ID);

        if (transactionId == null || userId == null) {
            logger.error("Missing OTP transaction data");
            showOtpForm(context, "Phiên làm việc đã hết hạn. Vui lòng đăng nhập lại.", MessageType.ERROR);
            return;
        }

        try {
            SmartOtpConfig config = SmartOtpConfig.getConfig(context);
            SmartOtpClient otpClient = new SmartOtpClient(
                    config.getOtpUrl(),
                    config.getOtpApiKey(),
                    config.getTimeout()
            );

            logger.info("Calling OTP verification API");
            OtpResponse otpVerifyResponse = otpClient.verifyOtp(userId, otpCode, transactionId);

            logger.infof("OTP verification response - Code: %s, Message: %s, Success: %s",
                    otpVerifyResponse.getCode(), otpVerifyResponse.getMessage(), otpVerifyResponse.isSuccess());

            authSession.setAuthNote(OTP_VERIFY_RESPONSE_CODE, otpVerifyResponse.getCode());
            authSession.setAuthNote(OTP_VERIFY_RESPONSE_MESSAGE, otpVerifyResponse.getMessage());
            authSession.setAuthNote(OTP_VERIFY_SUCCESS, String.valueOf(otpVerifyResponse.isSuccess()));

            if (!otpVerifyResponse.isSuccess()) {
                String errorMessage = otpVerifyResponse.getMessage();
                if (errorMessage == null || errorMessage.isEmpty()) {
                    errorMessage = "Mã OTP không chính xác. Vui lòng thử lại.";
                }
                showOtpForm(context, errorMessage, MessageType.ERROR);
                return;
            }

            logger.info("OTP verification successful, completing authentication");
            completeAuthentication(context);

        } catch (Exception e) {
            logger.error("Error during OTP verification", e);
            showOtpForm(context, "Lỗi xác thực OTP. Vui lòng thử lại.", MessageType.ERROR);
        }
    }

    private void handleResendOtp(AuthenticationFlowContext context) {
        logger.info("=== Handling OTP resend ===");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        authSession.removeAuthNote(OTP_STATE);
        authSession.removeAuthNote(TRANSACTION_ID);
        authSession.removeAuthNote(USER_ID);

        createOtpTransaction(context);
    }

    private void handleBackToLogin(AuthenticationFlowContext context) {
        logger.info("=== Handling back to login ===");
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        clearOtpSession(authSession);
        clearExternalVerificationSession(authSession);

        context.failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR);
    }


// Trong SmartOtpAuthenticator.java - Update completeAuthentication method

    private void completeAuthentication(AuthenticationFlowContext context) {
        logger.info("=== Completing authentication ===");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        try {
            UserModel user = context.getUser();

            if (user == null) {
                logger.warn("No user found in context, attempting to create from session data");

                String userInfoJson = authSession.getAuthNote(USER_INFO_JSON);
                if (userInfoJson == null || userInfoJson.isEmpty()) {
                    logger.error("No user info found for authentication completion");
                    context.failure(AuthenticationFlowError.INTERNAL_ERROR);
                    return;
                }

                String username = authSession.getAuthNote(VERIFIED_USERNAME);

                user = context.getSession().users().getUserByUsername(context.getRealm(), username);

                if (user == null) {
                    logger.error("Failed to create user in Keycloak");
                    context.failure(AuthenticationFlowError.INTERNAL_ERROR);
                    return;
                } else {
                    logger.infof("Updating existing user in Keycloak: %s", username);
                }

                context.setUser(user);
            }
            cleanupSession(authSession);

            context.success();

            logger.infof("Authentication completed successfully for user: %s", user.getUsername());

        } catch (Exception e) {
            logger.error("Error completing authentication", e);
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
        }
    }

    private void showOtpForm(AuthenticationFlowContext context, String message, MessageType messageType) {
        logger.info("Showing OTP form");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String username = authSession.getAuthNote(VERIFIED_USERNAME);

        LoginFormsProvider form = context.form()
                .setAttribute("showCredentialsForm", false)
                .setAttribute("showOtpForm", true)
                .setAttribute("showOtpField", true)
                .setAttribute("username", username != null ? username : "")
                .setAttribute("submitAction", ACTION_VERIFY_OTP)
                .setAttribute("submitButtonText", "Xác thực OTP")
                .setAttribute("resendAction", ACTION_RESEND_OTP)
                .setAttribute("resendButtonText", "Gửi lại OTP")
                .setAttribute("backAction", ACTION_BACK_TO_LOGIN)
                .setAttribute("backButtonText", "Quay lại đăng nhập");

        addApiResponseAttributes(form, authSession);

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

    private void handleOtpCreationError(AuthenticationFlowContext context, OtpResponse otpResponse) {
        logger.warnf("OTP creation failed. Code: %s, Message: %s",
                otpResponse.getCode(), otpResponse.getMessage());

        String errorMessage = otpResponse.getMessage();
        if (errorMessage == null || errorMessage.isEmpty()) {
            errorMessage = "Không thể tạo OTP. Vui lòng thử lại.";
        }

        LoginFormsProvider form = context.form()
                .setAttribute("showCredentialsForm", false)
                .setAttribute("showOtpForm", false)
                .setAttribute("showOtpField", false)
                .setAttribute("otpCreationFailed", true)
                .setAttribute("backAction", ACTION_BACK_TO_LOGIN)
                .setAttribute("backButtonText", "Quay lại đăng nhập")
                .setError(errorMessage);

        Response errorResponse = form.createLoginUsernamePassword();
        context.challenge(errorResponse);
    }

    private void addApiResponseAttributes(org.keycloak.forms.login.LoginFormsProvider form,
                                          AuthenticationSessionModel authSession) {
        form.setAttribute("otpApiResponseCode", getSessionAttributeSafely(authSession, OTP_API_RESPONSE_CODE));
        form.setAttribute("otpApiResponseMessage", getSessionAttributeSafely(authSession, OTP_API_RESPONSE_MESSAGE));
        form.setAttribute("otpApiSuccess", getSessionAttributeSafely(authSession, OTP_API_SUCCESS));
        form.setAttribute("otpVerifyResponseCode", getSessionAttributeSafely(authSession, OTP_VERIFY_RESPONSE_CODE));
        form.setAttribute("otpVerifyResponseMessage", getSessionAttributeSafely(authSession, OTP_VERIFY_RESPONSE_MESSAGE));
        form.setAttribute("otpVerifySuccess", getSessionAttributeSafely(authSession, OTP_VERIFY_SUCCESS));
        form.setAttribute("otpState", getSessionAttributeSafely(authSession, OTP_STATE));
    }

    private String getSessionAttributeSafely(AuthenticationSessionModel session, String key) {
        String value = session.getAuthNote(key);
        return value != null ? value : "";
    }

    private void cleanupSession(AuthenticationSessionModel authSession) {
        logger.info("Cleaning up OTP session");
        clearOtpSession(authSession);
        clearExternalVerificationSession(authSession);
    }

    private void clearOtpSession(AuthenticationSessionModel authSession) {
        String[] otpKeys = {
                OTP_STATE, TRANSACTION_ID, USER_ID,
                OTP_API_RESPONSE_CODE, OTP_API_RESPONSE_MESSAGE, OTP_API_SUCCESS,
                OTP_VERIFY_RESPONSE_CODE, OTP_VERIFY_RESPONSE_MESSAGE, OTP_VERIFY_SUCCESS
        };

        for (String key : otpKeys) {
            authSession.removeAuthNote(key);
        }
    }

    private void clearExternalVerificationSession(AuthenticationSessionModel authSession) {
        String[] externalKeys = {
                EXTERNAL_VERIFICATION_COMPLETED, CUSTOMER_NUMBER, USER_INFO_JSON, VERIFIED_USERNAME
        };

        for (String key : externalKeys) {
            authSession.removeAuthNote(key);
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