package com.example.keycloak.ocb.authenticate;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class OcbUserVerificationAuthenticatorFactory implements AuthenticatorFactory {

    public static final String CONFIG_API_URL = "apiUrl";
    public static final String CONFIG_API_USERNAME = "apiUsername";
    public static final String CONFIG_API_PASSWORD = "apiPassword";
    public static final String CONFIG_TIMEOUT = "timeout";

    public static final String PROVIDER_ID = "ocb-user-verification";

    private static final OcbUserVerificationAuthenticator SINGLETON = new OcbUserVerificationAuthenticator();

    @Override
    public String getDisplayType() {
        return "OCB User Verification (via API)";
    }

    @Override
    public String getReferenceCategory() {
        return "OCB API";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[]{
                AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.ALTERNATIVE,
                AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Xác thực username/password qua OCB API. Step này sẽ lưu thông tin user vào session cho các step tiếp theo.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        List<ProviderConfigProperty> config = new ArrayList<>();

        ProviderConfigProperty apiUrl = new ProviderConfigProperty();
        apiUrl.setName(CONFIG_API_URL);
        apiUrl.setLabel("OCB API URL");
        apiUrl.setType(ProviderConfigProperty.STRING_TYPE);
        apiUrl.setHelpText("URL của OCB endpoint để xác thực username/password");
        config.add(apiUrl);

        ProviderConfigProperty apiUsername = new ProviderConfigProperty();
        apiUsername.setName(CONFIG_API_USERNAME);
        apiUsername.setLabel("OCB API Username");
        apiUsername.setType(ProviderConfigProperty.STRING_TYPE);
        apiUsername.setHelpText("Username để xác thực với OCB (Basic Authentication)");
        config.add(apiUsername);

        ProviderConfigProperty apiPassword = new ProviderConfigProperty();
        apiPassword.setName(CONFIG_API_PASSWORD);
        apiPassword.setLabel("OCB API Password");
        apiPassword.setType(ProviderConfigProperty.PASSWORD);
        apiPassword.setHelpText("Password để xác thực với OCB (Basic Authentication)");
        config.add(apiPassword);

        ProviderConfigProperty timeout = new ProviderConfigProperty();
        timeout.setName(CONFIG_TIMEOUT);
        timeout.setLabel("API Timeout (seconds)");
        timeout.setType(ProviderConfigProperty.STRING_TYPE);
        timeout.setHelpText("Timeout cho API calls đến OCB (mặc định: 10 giây)");
        timeout.setDefaultValue("10");
        config.add(timeout);

        return config;
    }

    @Override
    public Authenticator create(KeycloakSession keycloakSession) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope scope) {
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}