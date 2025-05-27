package com.example.keycloak.corp;

import com.example.keycloak.constant.ResponseCodes;
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

        RetryLogicHandler.LockoutStatus lockoutStatus =
                RetryLogicHandler.checkLockoutStatus(context, identifier, "otp");

        if (lockoutStatus.isLocked()) {
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("identifier", maskPhone(phone));
            responseData.put("remainingLockoutMs", lockoutStatus.getRemainingLockoutMs());
            responseData.put("failedAttempts", lockoutStatus.getFailedAttempts());

            Response challengeResponse = challenge(context, ResponseCodes.OTP_ACCOUNT_LOCKED, responseData);
            context.challenge(challengeResponse);
            return;
        }

        if (!canResendOTP(context)) {
            long remainingSeconds = getResendCoolDownRemaining(context);
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("cooldownSeconds", remainingSeconds);
            responseData.put("phone", maskPhone(phone));

            Response challengeResponse = challenge(context, ResponseCodes.OTP_RESEND_COOLDOWN, responseData);
            context.challenge(challengeResponse);
            return;
        }

        try {
            String otpSession = generateOTPSession(context);

            boolean otpSent = sendOTP(context, otpSession, phone);
            if (!otpSent) {
                Map<String, Object> responseData = new HashMap<>();
                responseData.put("phone", maskPhone(phone));

                Response challengeResponse = challenge(context, ResponseCodes.OTP_SEND_FAILED, responseData);
                context.challenge(challengeResponse);
                return;
            }

            context.getAuthenticationSession().setAuthNote("otpSession", otpSession);
            context.getAuthenticationSession().setAuthNote("otpSentTime", String.valueOf(System.currentTimeMillis()));

            logger.infof("OTP sent successfully to phone: %s with session: %s", maskPhone(phone), otpSession);

            Map<String, Object> responseData = new HashMap<>();
            responseData.put("phone", maskPhone(phone));
            responseData.put("otpLength", getConfigValue(context.getAuthenticatorConfig(), OTPAuthenticatorFactory.OTP_LENGTH, "6"));
            responseData.put("canResend", true);
            responseData.put("resendCooldown", 0);

            Response challengeResponse = challenge(context, ResponseCodes.OTP_SENT, responseData);
            context.challenge(challengeResponse);

        } catch (Exception e) {
            logger.errorf(e, "Failed to send OTP");
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("phone", maskPhone(phone));
            responseData.put("error", ResponseCodes.NETWORK_ERROR);

            Response challengeResponse = challenge(context, ResponseCodes.OTP_SEND_ERROR, responseData);
            context.challenge(challengeResponse);
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String identifier = context.getAuthenticationSession().getAuthNote("identifier");
        String phone = context.getAuthenticationSession().getAuthNote("phone");

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
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("field", "otp");
            responseData.put("fieldName", "Mã OTP");
            responseData.put("phone", maskPhone(phone));

            Response challengeResponse = challenge(context, ResponseCodes.FIELD_REQUIRED, responseData);
            context.challenge(challengeResponse);
            return;
        }

        String expectedLength = getConfigValue(context.getAuthenticatorConfig(), OTPAuthenticatorFactory.OTP_LENGTH, "6");
        String otpPattern = "^[0-9]{" + expectedLength + "}$";
        if (!otp.matches(otpPattern)) {
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("field", "otp");
            responseData.put("expectedLength", expectedLength);
            responseData.put("phone", maskPhone(phone));
            responseData.put("format", "Mã OTP phải là " + expectedLength + " chữ số");

            Response challengeResponse = challenge(context, ResponseCodes.OTP_INVALID_FORMAT, responseData);
            context.challenge(challengeResponse);
            return;
        }

        String otpSession = context.getAuthenticationSession().getAuthNote("otpSession");
        if (otpSession == null) {
            logger.error("Missing OTP session");
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
            return;
        }

        try {
            boolean isValid = verifyOTP(context, otpSession, otp);
            if (isValid) {
                RetryLogicHandler.resetFailedAttempts(context, identifier, "otp");
                logger.infof("OTP verification successful for identifier: %s", identifier);
                context.success();
            } else {
                RetryLogicHandler.LockoutResult lockoutResult =
                        RetryLogicHandler.recordFailedAttempt(context, identifier, "otp");

                Map<String, Object> responseData = new HashMap<>();
                responseData.put("attemptCount", lockoutResult.getAttemptCount());
                responseData.put("maxAttempts", lockoutResult.getMaxAttempts());
                responseData.put("isLocked", lockoutResult.isLocked());
                responseData.put("phone", maskPhone(phone));

                if (lockoutResult.isLocked()) {
                    responseData.put("lockoutDurationMinutes", lockoutResult.getLockoutDurationMinutes());
                    responseData.put("lockoutUntil", lockoutResult.getLockoutUntil());
                }

                String responseCode = lockoutResult.isLocked() ? ResponseCodes.OTP_INVALID_LOCKED : ResponseCodes.OTP_INVALID;
                Response challengeResponse = challenge(context, responseCode, responseData);
                context.challenge(challengeResponse);
            }
        } catch (Exception e) {
            logger.errorf(e, "OTP verification failed due to exception");

            Map<String, Object> responseData = new HashMap<>();
            responseData.put("phone", maskPhone(phone));
            responseData.put("error", ResponseCodes.NETWORK_ERROR);

            Response challengeResponse = challenge(context, ResponseCodes.OTP_VERIFY_ERROR, responseData);
            context.challenge(challengeResponse);
        }
    }

    private boolean canResendOTP(AuthenticationFlowContext context) {
        String lastSentStr = context.getAuthenticationSession().getAuthNote("otpSentTime");
        if (lastSentStr == null) {
            return true;
        }

        long lastSent = Long.parseLong(lastSentStr);
        long coolDownMs = getOTPResendCoolDownSeconds(context.getAuthenticatorConfig()) * 1000L;

        return (System.currentTimeMillis() - lastSent) >= coolDownMs;
    }

    private long getResendCoolDownRemaining(AuthenticationFlowContext context) {
        String lastSentStr = context.getAuthenticationSession().getAuthNote("otpSentTime");
        if (lastSentStr == null) {
            return 0;
        }

        long lastSent = Long.parseLong(lastSentStr);
        long coolDownMs = getOTPResendCoolDownSeconds(context.getAuthenticatorConfig()) * 1000L;
        long elapsed = System.currentTimeMillis() - lastSent;

        return Math.max(0, (coolDownMs - elapsed) / 1000);
    }

    private String generateOTPSession(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        String prefix = getConfigValue(config, OTPAuthenticatorFactory.OTP_SESSION_PREFIX, "VPB");
        return prefix + System.currentTimeMillis() + UUID.randomUUID().toString().substring(0, 8);
    }

    private boolean sendOTP(AuthenticationFlowContext context, String otpSession, String phone) throws IOException, InterruptedException {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();

        String requestBody = String.format("""
                        {
                            "OTPSession": "%s",
                            "OTPMethod": "%s",
                            "OTPReceiver": "%s",
                            "OTPLen": "%s",
                            "OTPType": "%s",
                            "brRequestID": "%s",
                            "OTPRequestor": "%s",
                            "paramList": ["%s"]
                        }
                        """,
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

        String requestBody = String.format("""
                        {
                            "OTPSession": "%s",
                            "OTPNumber": "%s",
                            "OTPRequestor": "%s"
                        }
                        """,
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

    private int getOTPResendCoolDownSeconds(AuthenticatorConfigModel config) {
        return Integer.parseInt(getConfigValue(config, OTPAuthenticatorFactory.OTP_RESEND_COOLDOWN_SECONDS, "30"));
    }

    private String maskPhone(String phone) {
        if (phone == null || phone.length() < 6) {
            return phone;
        }
        return phone.substring(0, 3) + "****" + phone.substring(phone.length() - 3);
    }

    protected Response challenge(AuthenticationFlowContext context, String responseCode, Map<String, Object> responseData) {
        LoginFormsProvider forms = context.form();

        if (responseCode != null) {
            forms.setAttribute("responseCode", responseCode);
            if (responseData != null) {
                forms.setAttribute("responseData", responseData);
            }
        }

        return forms.createForm("otp-form.ftl");
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