package com.example.keycloak.ocb.authenticate.config;

import com.example.keycloak.ocb.authenticate.OcbUserVerificationAuthenticatorFactory;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;

public class OcbVerificationConfig {
    private static final Logger logger = Logger.getLogger(OcbVerificationConfig.class);
    private static final int DEFAULT_TIMEOUT = 10; // 10 seconds

    private final String apiUrl;
    private final String apiUsername;
    private final String apiPassword;
    private final int timeout;

    private final boolean isLastStep;


    private OcbVerificationConfig(String apiUrl, String apiUsername, String apiPassword, int timeout, boolean isLastStep) {
        this.apiUrl = apiUrl;
        this.apiUsername = apiUsername;
        this.apiPassword = apiPassword;
        this.timeout = timeout;
        this.isLastStep = isLastStep;
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

    public boolean getIsLatStep() {
        return isLastStep;
    }


    public static OcbVerificationConfig getConfig(AuthenticationFlowContext context) {
        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();

        if (configModel == null || configModel.getConfig() == null) {
            logger.warn("No configuration found for External User Verification authenticator");
            return new OcbVerificationConfig("", "", "", DEFAULT_TIMEOUT, false);
        }

        String apiUrl = configModel.getConfig().get(OcbUserVerificationAuthenticatorFactory.CONFIG_API_URL);
        String apiUsername = configModel.getConfig().get(OcbUserVerificationAuthenticatorFactory.CONFIG_API_USERNAME);
        String apiPassword = configModel.getConfig().get(OcbUserVerificationAuthenticatorFactory.CONFIG_API_PASSWORD);
        String timeoutStr = configModel.getConfig().get(OcbUserVerificationAuthenticatorFactory.CONFIG_TIMEOUT);
        String isLastStepStr = configModel.getConfig().get(OcbUserVerificationAuthenticatorFactory.CONFIG_IS_LAST_STEP);
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


        if (apiUrl == null || apiUrl.isEmpty()) {
            logger.error("API URL is not configured for External User Verification");
        }

        if (apiUsername == null || apiUsername.isEmpty() || apiPassword == null || apiPassword.isEmpty()) {
            logger.warn("API credentials may not be properly configured for External User Verification");
        }
        boolean isLastStep = false;
        if (isLastStepStr != null && !isLastStepStr.isEmpty()) {
            isLastStep = Boolean.parseBoolean(isLastStepStr);
        }

        return new OcbVerificationConfig(
                apiUrl, apiUsername, apiPassword, timeout, isLastStep
        );
    }

    public boolean isValid() {
        return apiUrl != null && !apiUrl.isEmpty()
                && apiUsername != null && !apiUsername.isEmpty()
                && apiPassword != null && !apiPassword.isEmpty();
    }

}