package com.example.keycloak.corp;

import com.example.keycloak.constant.ResponseCodes;
import com.example.keycloak.util.ResponseMessageHandler;
import com.example.keycloak.util.RetryLogicHandler;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class OTPAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(OTPAuthenticator.class);
    private static final String OTP_PARAM = "otp";

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String legalId = context.getAuthenticationSession().getAuthNote("legalId");
        String phone = context.getAuthenticationSession().getAuthNote("phone");
        String identifier = context.getAuthenticationSession().getAuthNote("identifier");

        if (legalId == null || phone == null) {
            logger.error("Missing legalId or phone in session");
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
            return;
        }

        UserModel user = context.getUser();
        if (user == null) {
            logger.error("No user found in context for OTP authentication");
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
            return;
        }

        RetryLogicHandler.LockoutStatus lockoutStatus =
                RetryLogicHandler.checkLockoutStatus(context, identifier, "otp");

        if (lockoutStatus.isLocked()) {
            Map<String, Object> responseData = ResponseMessageHandler.createOTPLockoutResponse(
                    lockoutStatus.getLockedAt(),
                    lockoutStatus.getLockDurationSeconds(),
                    lockoutStatus.getFailedAttempts()
            );

            Response challengeResponse = challenge(context, ResponseCodes.OTP_ACCOUNT_LOCKED, responseData);
            context.challenge(challengeResponse);
            return;
        }

        if (!canResendOTP(user)) {
            long remainingSeconds = getResendCoolDownRemaining(user);
            Map<String, Object> responseData = ResponseMessageHandler.createResendCooldownResponse(remainingSeconds);

            Response challengeResponse = challenge(context, ResponseCodes.OTP_RESEND_COOLDOWN, responseData);
            context.challenge(challengeResponse);
            return;
        }

        if (!canRequestOTP(user)) {
            Map<String, Object> responseData = ResponseMessageHandler.createOTPRequestLimitResponse();
            Response challengeResponse = challenge(context, ResponseCodes.OTP_REQUEST_LIMIT_EXCEEDED, responseData);
            context.challenge(challengeResponse);
            return;
        }

        try {
            String otpSession = generateOTPSession(context);

            boolean otpSent = sendOTP(context, otpSession, phone);
            if (!otpSent) {
                Map<String, Object> responseData = ResponseMessageHandler.createOTPSendFailedResponse();
                Response challengeResponse = challenge(context, ResponseCodes.OTP_SEND_FAILED, responseData);
                context.challenge(challengeResponse);
                return;
            }

            incrementOTPRequestCount(user);

            user.setAttribute("otpSession", List.of(otpSession));
            user.setAttribute("otpSentTime", List.of(String.valueOf(System.currentTimeMillis())));

            logger.infof("OTP sent successfully to phone: %s with session: %s", ResponseMessageHandler.maskPhone(phone), otpSession);

            Map<String, Object> responseData = ResponseMessageHandler.createOTPSentResponse(phone);
            Response challengeResponse = challenge(context, ResponseCodes.OTP_SENT, responseData);
            context.challenge(challengeResponse);

        } catch (Exception e) {
            logger.errorf(e, "Failed to send OTP");
            Response challengeResponse = challenge(context, ResponseCodes.OTP_SEND_ERROR, null);
            context.challenge(challengeResponse);
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String identifier = context.getAuthenticationSession().getAuthNote("identifier");

        UserModel user = context.getUser();
        if (user == null) {
            logger.error("No user found in context for OTP action");
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
            return;
        }

        if (formData.containsKey("cancel")) {
            context.resetFlow();
            return;
        }

        if (formData.containsKey("resend")) {
            authenticate(context);
            return;
        }

        String otp = formData.getFirst(OTP_PARAM);
        if (otp == null || otp.trim().isEmpty()) {
            Response challengeResponse = challenge(context, ResponseCodes.FIELD_REQUIRED, null);
            context.challenge(challengeResponse);
            return;
        }

        String expectedLength = getConfigValue(context.getAuthenticatorConfig(), OTPAuthenticatorFactory.OTP_LENGTH, "6");
        String otpPattern = "^[0-9]{" + expectedLength + "}$";
        if (!otp.matches(otpPattern)) {
            Response challengeResponse = challenge(context, ResponseCodes.OTP_INVALID_FORMAT, null);
            context.challenge(challengeResponse);
            return;
        }

        List<String> otpSessionList = user.getAttributes().get("otpSession");
        if (otpSessionList == null || otpSessionList.isEmpty()) {
            logger.error("Missing OTP session in user attributes");
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
            return;
        }
        String otpSession = otpSessionList.get(0);

        try {
            boolean isValid = verifyOTP(context, otpSession, otp);
            if (isValid) {
                RetryLogicHandler.resetFailedAttempts(context, identifier, "otp");
                user.removeAttribute("otpSession");
                user.removeAttribute("otpSentTime");

                logger.infof("OTP verification successful for user: %s", user.getUsername());
                context.success();
            } else {
                RetryLogicHandler.LockoutResult lockoutResult =
                        RetryLogicHandler.recordFailedAttempt(context, identifier, "otp");

                if (lockoutResult.isLocked()) {
                    Map<String, Object> responseData = ResponseMessageHandler.createOTPLockoutResponse(
                            lockoutResult.getLockedAt(),
                            lockoutResult.getLockDurationSeconds(),
                            lockoutResult.getAttemptCount()
                    );

                    Response challengeResponse = challenge(context, ResponseCodes.OTP_INVALID_LOCKED, responseData);
                    context.challenge(challengeResponse);
                } else {
                    Map<String, Object> responseData = ResponseMessageHandler.createOTPInvalidResponse();
                    Response challengeResponse = challenge(context, ResponseCodes.OTP_INVALID, responseData);
                    context.challenge(challengeResponse);
                }
            }
        } catch (Exception e) {
            logger.errorf(e, "OTP verification failed due to exception");
            Response challengeResponse = challenge(context, ResponseCodes.OTP_VERIFY_ERROR, null);
            context.challenge(challengeResponse);
        }
    }

    private void incrementOTPRequestCount(UserModel user) {
        List<String> requestCountList = user.getAttributes().get("otpRequestCount");
        int currentCount = 0;

        if (requestCountList != null && !requestCountList.isEmpty()) {
            try {
                currentCount = Integer.parseInt(requestCountList.get(0));
            } catch (NumberFormatException e) {
                logger.warn("Invalid OTP request count format, resetting count", e);
                user.removeAttribute("otpRequestCount");
                user.removeAttribute("otpRequestResetTime");
            }
        }

        currentCount++;
        user.setAttribute("otpRequestCount", List.of(String.valueOf(currentCount)));

        if (currentCount == 1) {
            user.setAttribute("otpRequestResetTime", List.of(String.valueOf(System.currentTimeMillis())));
        }
    }

    private boolean canRequestOTP(UserModel user) {
        List<String> requestCountList = user.getAttributes().get("otpRequestCount");
        List<String> requestResetTimeList = user.getAttributes().get("otpRequestResetTime");

        long currentTime = System.currentTimeMillis();
        long oneHourMs = 60 * 60 * 1000L;

        if (requestResetTimeList != null && !requestResetTimeList.isEmpty()) {
            try {
                long resetTime = Long.parseLong(requestResetTimeList.get(0));
                if (currentTime - resetTime >= oneHourMs) {
                    user.removeAttribute("otpRequestCount");
                    user.removeAttribute("otpRequestResetTime");
                    return true;
                }
            } catch (NumberFormatException e) {
                user.removeAttribute("otpRequestCount");
                user.removeAttribute("otpRequestResetTime");
                return true;
            }
        }

        if (requestCountList != null && !requestCountList.isEmpty()) {
            try {
                int requestCount = Integer.parseInt(requestCountList.get(0));
                return requestCount < 5; // Limit 5 requests per hour
            } catch (NumberFormatException e) {
                return true;
            }
        }

        return true;
    }

    private boolean canResendOTP(UserModel user) {
        List<String> sentTimeList = user.getAttributes().get("otpSentTime");
        if (sentTimeList == null || sentTimeList.isEmpty()) {
            return true;
        }

        try {
            long lastSent = Long.parseLong(sentTimeList.get(0));
            long coolDownMs = 30 * 1000L;
            return (System.currentTimeMillis() - lastSent) >= coolDownMs;
        } catch (NumberFormatException e) {
            return true;
        }
    }

    private long getResendCoolDownRemaining(UserModel user) {
        List<String> sentTimeList = user.getAttributes().get("otpSentTime");
        if (sentTimeList == null || sentTimeList.isEmpty()) {
            return 0;
        }

        try {
            long lastSent = Long.parseLong(sentTimeList.get(0));
            long coolDownMs = 30 * 1000L; // Default 30 seconds
            long elapsed = System.currentTimeMillis() - lastSent;
            return Math.max(0, (coolDownMs - elapsed) / 1000);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private String generateOTPSession(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        String prefix = getConfigValue(config, OTPAuthenticatorFactory.OTP_SESSION_PREFIX, "VPB");
        return prefix + System.currentTimeMillis() + UUID.randomUUID().toString().substring(0, 8);
    }

    private boolean sendOTP(AuthenticationFlowContext context, String otpSession, String phone) throws IOException, InterruptedException {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();

        String requestBody = String.format(
                "{\n" +
                        "    \"OTPSession\": \"%s\",\n" +
                        "    \"OTPMethod\": \"%s\",\n" +
                        "    \"OTPReceiver\": \"%s\",\n" +
                        "    \"OTPLen\": \"%s\",\n" +
                        "    \"OTPType\": \"%s\",\n" +
                        "    \"brRequestID\": \"%s\",\n" +
                        "    \"OTPRequestor\": \"%s\",\n" +
                        "    \"paramList\": [\"%s\"]\n" +
                        "}",
                otpSession,
                getConfigValue(config, OTPAuthenticatorFactory.OTP_METHOD, "1"),
                phone,
                getConfigValue(config, OTPAuthenticatorFactory.OTP_LENGTH, "6"),
                getConfigValue(config, OTPAuthenticatorFactory.OTP_TYPE, "ECM"),
                getConfigValue(config, OTPAuthenticatorFactory.OTP_BR_REQUEST_ID, "VN0010242"),
                getConfigValue(config, OTPAuthenticatorFactory.OTP_REQUESTOR, "ECM"),
                getConfigValue(config, OTPAuthenticatorFactory.OTP_PARAM_LIST, "TEST")
        );

        String requestId = getConfigValue(config, OTPAuthenticatorFactory.OTP_REQUEST_ID_PREFIX, "DMS") + System.currentTimeMillis();
        String assignUrl = getConfigValue(config, OTPAuthenticatorFactory.OTP_ASSIGN_URL, "http://10.37.16.153:7111/api/ibps/otp/assign");

        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(assignUrl))
                .header("X-Request-Id", requestId)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody));

        HttpRequest request = requestBuilder.build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        logger.infof("OTP assign response: %d - %s", response.statusCode(), response.body());

        if (response.statusCode() == 200) {
            JsonNode jsonResponse = objectMapper.readTree(response.body());
            String error = jsonResponse.get("error").asText();
            return "0".equals(error);
        }

        return false;
    }

    private boolean verifyOTP(AuthenticationFlowContext context, String otpSession, String otp) throws IOException, InterruptedException {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();

        String requestBody = String.format(
                "{\n" +
                        "    \"OTPSession\": \"%s\",\n" +
                        "    \"OTPNumber\": \"%s\",\n" +
                        "    \"OTPRequestor\": \"%s\"\n" +
                        "}",
                otpSession,
                otp,
                getConfigValue(config, OTPAuthenticatorFactory.OTP_REQUESTOR, "ECM")
        );

        String requestId = getConfigValue(config, OTPAuthenticatorFactory.OTP_REQUEST_ID_PREFIX, "DMS") + System.currentTimeMillis();
        String verifyUrl = getConfigValue(config, OTPAuthenticatorFactory.OTP_VERIFY_URL, "http://10.37.16.153:7111/api/ibps/otp/verify");
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(verifyUrl))
                .header("X-Request-Id", requestId)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody));
        HttpRequest request = requestBuilder.build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        logger.infof("OTP verify response: %d - %s", response.statusCode(), response.body());

        if (response.statusCode() == 200) {
            JsonNode jsonResponse = objectMapper.readTree(response.body());
            String error = jsonResponse.get("error").asText();
            return "0".equals(error);
        }

        return false;
    }

    private String getConfigValue(AuthenticatorConfigModel config, String key, String defaultValue) {
        if (config == null || config.getConfig() == null) {
            return defaultValue;
        }
        return config.getConfig().getOrDefault(key, defaultValue);
    }

    protected Response challenge(AuthenticationFlowContext context, String responseCode, Map<String, Object> responseData) {
        LoginFormsProvider forms = context.form();

        if (responseCode != null) {
            forms.setAttribute("responseCode", responseCode);
            if (responseData != null) {
                forms.setAttribute("responseData", responseData);
            }
        }

        return forms.createForm("custom-otp-form.ftl");
    }

    @Override
    public boolean requiresUser() {
        return true;
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