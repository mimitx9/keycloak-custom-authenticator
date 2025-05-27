package com.example.keycloak.ocb.auth;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;

public class ExternalVerificationConfig {
    private static final Logger logger = Logger.getLogger(ExternalVerificationConfig.class);

    private final String apiUrl;
    private final String apiUsername;
    private final String apiPassword;
    private final String targetClientId;

    private ExternalVerificationConfig(String apiUrl, String apiUsername, String apiPassword, String targetClientId) {
        this.apiUrl = apiUrl;
        this.apiUsername = apiUsername;
        this.apiPassword = apiPassword;
        this.targetClientId = targetClientId;
    }

    public String getApiUrl() {
        return apiUrl;
    }

    public String getApiUsername() {
        return apiUsername;
    }

    public String getApiPassword() {
        return apiPassword;
    }

    public String getTargetClientId() {
        return targetClientId;
    }

    public static ExternalVerificationConfig getConfig(AuthenticationFlowContext context) {
        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();

        if (configModel == null || configModel.getConfig() == null) {
            logger.warn("No configuration found for External User Verification authenticator");
            return new ExternalVerificationConfig("", "", "", "");
        }

        String apiUrl = configModel.getConfig().get(ExternalUserVerificationAuthenticatorFactory.CONFIG_API_URL);
        String apiUsername = configModel.getConfig().get(ExternalUserVerificationAuthenticatorFactory.CONFIG_API_USERNAME);
        String apiPassword = configModel.getConfig().get(ExternalUserVerificationAuthenticatorFactory.CONFIG_API_PASSWORD);
        String targetClientId = configModel.getConfig().get(ExternalUserVerificationAuthenticatorFactory.CONFIG_TARGET_CLIENT_ID);

        if (apiUrl == null || apiUrl.isEmpty()) {
            logger.error("API URL is not configured for External User Verification");
        }

        if (apiUsername == null || apiUsername.isEmpty() || apiPassword == null || apiPassword.isEmpty()) {
            logger.warn("API credentials may not be properly configured for External User Verification");
        }

        if (targetClientId == null || targetClientId.isEmpty()) {
            logger.warn("Target Client ID is not configured for External User Verification");
        }

        return new ExternalVerificationConfig(apiUrl, apiUsername, apiPassword, targetClientId);
    }

    public boolean isValid() {
        return apiUrl != null && !apiUrl.isEmpty()
                && apiUsername != null && !apiUsername.isEmpty()
                && apiPassword != null && !apiPassword.isEmpty()
                && targetClientId != null && !targetClientId.isEmpty();
    }
}