package com.example.keycloak.ocb.auth;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;

public class ExternalVerificationConfig {
    private static final Logger logger = Logger.getLogger(ExternalVerificationConfig.class);
    private static final int DEFAULT_TIMEOUT = 10; // 10 seconds

    private final String apiUrl;
    private final String apiUsername;
    private final String apiPassword;
    private final int timeout;

    // OTP configuration
    private final String otpUrl;
    private final String otpApiKey;
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

    private ExternalVerificationConfig(String apiUrl, String apiUsername, String apiPassword, int timeout,
                                       String otpUrl, String otpApiKey, String transactionData, int transactionTypeId,
                                       String challenge, String callbackUrl, int online, int push,
                                       String notificationTitle, String notificationBody, int esignerTypeId, int channelId, int maxOtpPerDay) {
        this.apiUrl = apiUrl;
        this.apiUsername = apiUsername;
        this.apiPassword = apiPassword;
        this.timeout = timeout;
        this.otpUrl = otpUrl;
        this.otpApiKey = otpApiKey;
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
    }

    // Original getters
    public String getApiUrl() {
        return apiUrl;
    }

    public String getApiUsername() {
        return apiUsername;
    }

    public String getApiPassword() {
        return apiPassword;
    }

    public int getTimeout() {
        return timeout;
    }

    // OTP getters
    public String getOtpUrl() {
        return otpUrl;
    }

    public String getOtpApiKey() {
        return otpApiKey;
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

    public static ExternalVerificationConfig getConfig(AuthenticationFlowContext context) {
        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();

        if (configModel == null || configModel.getConfig() == null) {
            logger.warn("No configuration found for External User Verification authenticator");
            return new ExternalVerificationConfig("", "", "", DEFAULT_TIMEOUT,
                    "", "", "", 0, "", "", 0, 0, "", "", 0, 0, 0);
        }

        String apiUrl = configModel.getConfig().get(ExternalUserVerificationAuthenticatorFactory.CONFIG_API_URL);
        String apiUsername = configModel.getConfig().get(ExternalUserVerificationAuthenticatorFactory.CONFIG_API_USERNAME);
        String apiPassword = configModel.getConfig().get(ExternalUserVerificationAuthenticatorFactory.CONFIG_API_PASSWORD);
        String timeoutStr = configModel.getConfig().get(ExternalUserVerificationAuthenticatorFactory.CONFIG_TIMEOUT);

        String otpUrl = configModel.getConfig().get(ExternalUserVerificationAuthenticatorFactory.CONFIG_OTP_URL);
        String otpApiKey = configModel.getConfig().get(ExternalUserVerificationAuthenticatorFactory.CONFIG_OTP_API_KEY);
        String transactionData = configModel.getConfig().get(ExternalUserVerificationAuthenticatorFactory.CONFIG_TRANSACTION_DATA);
        String transactionTypeIdStr = configModel.getConfig().get(ExternalUserVerificationAuthenticatorFactory.CONFIG_TRANSACTION_TYPE_ID);
        String challenge = configModel.getConfig().get(ExternalUserVerificationAuthenticatorFactory.CONFIG_CHALLENGE);
        String callbackUrl = configModel.getConfig().get(ExternalUserVerificationAuthenticatorFactory.CONFIG_CALLBACK_URL);
        String onlineStr = configModel.getConfig().get(ExternalUserVerificationAuthenticatorFactory.CONFIG_ONLINE);
        String pushStr = configModel.getConfig().get(ExternalUserVerificationAuthenticatorFactory.CONFIG_PUSH);
        String notificationTitle = configModel.getConfig().get(ExternalUserVerificationAuthenticatorFactory.CONFIG_NOTIFICATION_TITLE);
        String notificationBody = configModel.getConfig().get(ExternalUserVerificationAuthenticatorFactory.CONFIG_NOTIFICATION_BODY);
        String esignerTypeIdStr = configModel.getConfig().get(ExternalUserVerificationAuthenticatorFactory.CONFIG_ESIGNER_TYPE_ID);
        String channelIdStr = configModel.getConfig().get(ExternalUserVerificationAuthenticatorFactory.CONFIG_CHANNEL_ID);
        String maxOtpPerDayStr = configModel.getConfig().get(ExternalUserVerificationAuthenticatorFactory.CONFIG_MAX_OTP_PER_DAY);

        int timeout = DEFAULT_TIMEOUT;
        if (timeoutStr != null && !timeoutStr.isEmpty()) {
            try {
                timeout = Integer.parseInt(timeoutStr);
                if (timeout <= 0) {
                    logger.warn("Invalid timeout value: " + timeoutStr + ", using default: " + DEFAULT_TIMEOUT);
                    timeout = DEFAULT_TIMEOUT;
                }
            } catch (NumberFormatException e) {
                logger.warn("Invalid timeout format: " + timeoutStr + ", using default: " + DEFAULT_TIMEOUT);
                timeout = DEFAULT_TIMEOUT;
            }
        }

        int transactionTypeId = parseIntSafely(transactionTypeIdStr, 1, "transactionTypeId");
        int online = parseIntSafely(onlineStr, 0, "online");
        int push = parseIntSafely(pushStr, 1, "push");
        int esignerTypeId = parseIntSafely(esignerTypeIdStr, 6, "esignerTypeId");
        int channelId = parseIntSafely(channelIdStr, 1, "channelId");
        int maxOtpPerDay = parseIntSafely(maxOtpPerDayStr, 100, "maxOtpPerDay");
        if (otpUrl == null) otpUrl = "";
        if (otpApiKey == null) otpApiKey = "";
        if (transactionData == null) transactionData = "1|CCP|Login|0";
        if (challenge == null) challenge = "";
        if (callbackUrl == null) callbackUrl = "";
        if (notificationTitle == null) notificationTitle = "Transaction confirmation";
        if (notificationBody == null)
            notificationBody = "You are making transaction on VPBank NEO. Please confirm the transaction.";

        if (apiUrl == null || apiUrl.isEmpty()) {
            logger.error("API URL is not configured for External User Verification");
        }

        if (apiUsername == null || apiUsername.isEmpty() || apiPassword == null || apiPassword.isEmpty()) {
            logger.warn("API credentials may not be properly configured for External User Verification");
        }

        if (otpUrl.isEmpty()) {
            logger.error("OTP URL is not configured");
        }

        if (otpApiKey.isEmpty()) {
            logger.error("OTP API Key is not configured");
        }

        return new ExternalVerificationConfig(
                apiUrl, apiUsername, apiPassword, timeout,
                otpUrl, otpApiKey, transactionData, transactionTypeId,
                challenge, callbackUrl, online, push,
                notificationTitle, notificationBody, esignerTypeId, channelId, maxOtpPerDay
        );
    }

    private static int parseIntSafely(String value, int defaultValue, String fieldName) {
        if (value == null || value.isEmpty()) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            logger.warn("Invalid " + fieldName + " format: " + value + ", using default: " + defaultValue);
            return defaultValue;
        }
    }

    public boolean isValid() {
        return apiUrl != null && !apiUrl.isEmpty()
                && apiUsername != null && !apiUsername.isEmpty()
                && apiPassword != null && !apiPassword.isEmpty();
    }

    public boolean isOtpConfigValid() {
        return otpUrl != null && !otpUrl.isEmpty()
                && otpApiKey != null && !otpApiKey.isEmpty();
    }
}