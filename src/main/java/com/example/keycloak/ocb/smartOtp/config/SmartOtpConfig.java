package com.example.keycloak.ocb.smartOtp.config;

import com.example.keycloak.ocb.smartOtp.SmartOtpAuthenticatorFactory;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;

public class SmartOtpConfig {
    private static final Logger logger = Logger.getLogger(SmartOtpConfig.class);
    private static final int DEFAULT_TIMEOUT = 10; // 10 seconds

    private final String otpUrl;
    private final String otpApiKey;
    private final int timeout;
    private final String transactionData;
    private final int transactionTypeId;
    private final String challenge;
    private final String callbackUrl;
    private final int online;
    private final int push;
    private final String notificationTitle;
    private final String notificationBody;
    private final int esignerTypeId;
    private final int channelId;
    private final int maxOtpPerDay;
    private final String otpPrefix;


    private SmartOtpConfig(String otpUrl, String otpApiKey, int timeout,
                           String transactionData, int transactionTypeId, String challenge,
                           String callbackUrl, int online, int push, String notificationTitle,
                           String notificationBody, int esignerTypeId, int channelId, int maxOtpPerDay, String otpPrefix) {
        this.otpUrl = otpUrl;
        this.otpApiKey = otpApiKey;
        this.timeout = timeout;
        this.transactionData = transactionData;
        this.transactionTypeId = transactionTypeId;
        this.challenge = challenge;
        this.callbackUrl = callbackUrl;
        this.online = online;
        this.push = push;
        this.notificationTitle = notificationTitle;
        this.notificationBody = notificationBody;
        this.esignerTypeId = esignerTypeId;
        this.channelId = channelId;
        this.maxOtpPerDay = maxOtpPerDay;
        this.otpPrefix = otpPrefix;
    }

    // Getters
    public String getOtpUrl() {
        return otpUrl;
    }

    public String getOtpApiKey() {
        return otpApiKey;
    }

    public int getTimeout() {
        return timeout;
    }

    public String getTransactionData() {
        return transactionData;
    }

    public int getTransactionTypeId() {
        return transactionTypeId;
    }

    public String getChallenge() {
        return challenge;
    }

    public String getCallbackUrl() {
        return callbackUrl;
    }

    public int getOnline() {
        return online;
    }

    public int getPush() {
        return push;
    }

    public String getNotificationTitle() {
        return notificationTitle;
    }

    public String getNotificationBody() {
        return notificationBody;
    }

    public int getEsignerTypeId() {
        return esignerTypeId;
    }

    public int getChannelId() {
        return channelId;
    }

    public int getMaxOtpPerDay() {
        return maxOtpPerDay;
    }

    public String getOtpPrefix() {
        return otpPrefix;
    }

    public static SmartOtpConfig getConfig(AuthenticationFlowContext context) {
        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();

        if (configModel == null || configModel.getConfig() == null) {
            logger.warn("No configuration found for Smart OTP authenticator");
            return createDefaultConfig();
        }

        String otpUrl = configModel.getConfig().get(SmartOtpAuthenticatorFactory.CONFIG_OTP_URL);
        String otpApiKey = configModel.getConfig().get(SmartOtpAuthenticatorFactory.CONFIG_OTP_API_KEY);
        String timeoutStr = configModel.getConfig().get(SmartOtpAuthenticatorFactory.CONFIG_TIMEOUT);
        String transactionData = configModel.getConfig().get(SmartOtpAuthenticatorFactory.CONFIG_TRANSACTION_DATA);
        String transactionTypeIdStr = configModel.getConfig().get(SmartOtpAuthenticatorFactory.CONFIG_TRANSACTION_TYPE_ID);
        String challenge = configModel.getConfig().get(SmartOtpAuthenticatorFactory.CONFIG_CHALLENGE);
        String callbackUrl = configModel.getConfig().get(SmartOtpAuthenticatorFactory.CONFIG_CALLBACK_URL);
        String onlineStr = configModel.getConfig().get(SmartOtpAuthenticatorFactory.CONFIG_ONLINE);
        String pushStr = configModel.getConfig().get(SmartOtpAuthenticatorFactory.CONFIG_PUSH);
        String notificationTitle = configModel.getConfig().get(SmartOtpAuthenticatorFactory.CONFIG_NOTIFICATION_TITLE);
        String notificationBody = configModel.getConfig().get(SmartOtpAuthenticatorFactory.CONFIG_NOTIFICATION_BODY);
        String esignerTypeIdStr = configModel.getConfig().get(SmartOtpAuthenticatorFactory.CONFIG_ESIGNER_TYPE_ID);
        String channelIdStr = configModel.getConfig().get(SmartOtpAuthenticatorFactory.CONFIG_CHANNEL_ID);
        String maxOtpPerDayStr = configModel.getConfig().get(SmartOtpAuthenticatorFactory.CONFIG_MAX_OTP_PER_DAY);
        String otpPrefix = configModel.getConfig().get(SmartOtpAuthenticatorFactory.PREFIX_OTP);
        // Parse timeout
        int timeout = parseIntSafely(timeoutStr, DEFAULT_TIMEOUT, "timeout");
        if (timeout <= 0) {
            logger.warn("Invalid timeout value: " + timeoutStr + ", using default: " + DEFAULT_TIMEOUT);
            timeout = DEFAULT_TIMEOUT;
        }

        // Parse other integer values with defaults
        int transactionTypeId = parseIntSafely(transactionTypeIdStr, 1, "transactionTypeId");
        int online = parseIntSafely(onlineStr, 0, "online");
        int push = parseIntSafely(pushStr, 1, "push");
        int esignerTypeId = parseIntSafely(esignerTypeIdStr, 6, "esignerTypeId");
        int channelId = parseIntSafely(channelIdStr, 1, "channelId");
        int maxOtpPerDay = parseIntSafely(maxOtpPerDayStr, 100, "maxOtpPerDay");

        // Set defaults for null/empty strings
        if (otpUrl == null) otpUrl = "";
        if (otpApiKey == null) otpApiKey = "";
        if (transactionData == null || transactionData.isEmpty()) {
            transactionData = "1|CCP|Login|0";
        }
        if (challenge == null) challenge = "";
        if (callbackUrl == null) callbackUrl = "";
        if (notificationTitle == null || notificationTitle.isEmpty()) {
            notificationTitle = "Xác thực đăng nhập";
        }
        if (notificationBody == null || notificationBody.isEmpty()) {
            notificationBody = "Bạn đang thực hiện đăng nhập vào hệ thống. Vui lòng xác nhận giao dịch.";
        }

        // Log configuration validation
        if (otpUrl.isEmpty()) {
            logger.error("OTP URL is not configured for Smart OTP authenticator");
        }
        if (otpApiKey.isEmpty()) {
            logger.error("OTP API Key is not configured for Smart OTP authenticator");
        }
        if (otpPrefix.isEmpty()) {
            logger.warn("OTP prefix is not configured, using default");
        }
        logger.infof("Smart OTP Config loaded - URL: %s, API Key: %s, Timeout: %d, MaxOtpPerDay: %d",
                otpUrl, otpApiKey.isEmpty() ? "NOT_SET" : "SET", timeout, maxOtpPerDay);

        return new SmartOtpConfig(
                otpUrl, otpApiKey, timeout,
                transactionData, transactionTypeId, challenge, callbackUrl,
                online, push, notificationTitle, notificationBody,
                esignerTypeId, channelId, maxOtpPerDay, otpPrefix
        );
    }

    private static SmartOtpConfig createDefaultConfig() {
        logger.info("Creating default Smart OTP configuration");
        return new SmartOtpConfig(
                "", "", DEFAULT_TIMEOUT,
                "1|CCP|Login|0", 1, "", "",
                0, 1, "Xác thực đăng nhập",
                "Bạn đang thực hiện đăng nhập vào hệ thống. Vui lòng xác nhận giao dịch.",
                6, 1, 100, ""
        );
    }

    private static int parseIntSafely(String value, int defaultValue, String fieldName) {
        if (value == null || value.trim().isEmpty()) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            logger.warn("Invalid " + fieldName + " format: " + value + ", using default: " + defaultValue);
            return defaultValue;
        }
    }

    public boolean isValid() {
        boolean valid = otpUrl != null && !otpUrl.trim().isEmpty()
                && otpApiKey != null && !otpApiKey.trim().isEmpty();

        logger.infof("Smart OTP config validation: %s (URL: %s, API Key: %s)",
                valid ? "VALID" : "INVALID",
                otpUrl != null && !otpUrl.isEmpty() ? "SET" : "NOT_SET",
                otpApiKey != null && !otpApiKey.isEmpty() ? "SET" : "NOT_SET");

        return valid;
    }
}