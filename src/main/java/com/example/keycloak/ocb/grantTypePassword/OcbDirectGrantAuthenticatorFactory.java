package com.example.keycloak.ocb.grantTypePassword;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class OcbDirectGrantAuthenticatorFactory implements AuthenticatorFactory {

    public static final String CONFIG_ENABLE_EXTERNAL_AUTH = "enableExternalAuth";
    public static final String CONFIG_API_URL = "apiUrl";
    public static final String CONFIG_API_USERNAME = "apiUsername";
    public static final String CONFIG_API_PASSWORD = "apiPassword";
    public static final String CONFIG_TIMEOUT = "timeout";
    public static final String CONFIG_SYNC_PASSWORD = "syncPasswordToKeycloak";
    public static final String CONFIG_FALLBACK_TO_KEYCLOAK = "fallbackToKeycloak";

    public static final String PROVIDER_ID = "ocb-direct-grant-authenticator";

    private static final OcbDirectGrantAuthenticator SINGLETON = new OcbDirectGrantAuthenticator();

    @Override
    public String getDisplayType() {
        return "OCB External API Direct Grant";
    }

    @Override
    public String getReferenceCategory() {
        return PasswordCredentialModel.TYPE;
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
        return "Authenticator có thể toggle giữa OCB API và Keycloak authentication. Khi enable=true sẽ dùng OCB API, khi enable=false sẽ dùng Keycloak password verification.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        List<ProviderConfigProperty> config = new ArrayList<>();

        ProviderConfigProperty enableExternal = new ProviderConfigProperty();
        enableExternal.setName(CONFIG_ENABLE_EXTERNAL_AUTH);
        enableExternal.setLabel("Enable External Authentication");
        enableExternal.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        enableExternal.setHelpText("Bật/tắt xác thực qua OCB API. Khi tắt sẽ sử dụng Keycloak password verification");
        enableExternal.setDefaultValue("false");
        config.add(enableExternal);

        ProviderConfigProperty apiUrl = new ProviderConfigProperty();
        apiUrl.setName(CONFIG_API_URL);
        apiUrl.setLabel("OCB API URL");
        apiUrl.setType(ProviderConfigProperty.STRING_TYPE);
        apiUrl.setHelpText("URL của OCB endpoint để xác thực username/password (chỉ dùng khi Enable=true)");
        config.add(apiUrl);

        ProviderConfigProperty apiUsername = new ProviderConfigProperty();
        apiUsername.setName(CONFIG_API_USERNAME);
        apiUsername.setLabel("OCB API Username");
        apiUsername.setType(ProviderConfigProperty.STRING_TYPE);
        apiUsername.setHelpText("Username để xác thực với OCB API (Basic Authentication)");
        config.add(apiUsername);

        ProviderConfigProperty apiPassword = new ProviderConfigProperty();
        apiPassword.setName(CONFIG_API_PASSWORD);
        apiPassword.setLabel("OCB API Password");
        apiPassword.setType(ProviderConfigProperty.PASSWORD);
        apiPassword.setHelpText("Password để xác thực với OCB API (Basic Authentication)");
        config.add(apiPassword);

        ProviderConfigProperty timeout = new ProviderConfigProperty();
        timeout.setName(CONFIG_TIMEOUT);
        timeout.setLabel("API Timeout (seconds)");
        timeout.setType(ProviderConfigProperty.STRING_TYPE);
        timeout.setHelpText("Timeout cho API calls đến OCB (mặc định: 30 giây)");
        timeout.setDefaultValue("30");
        config.add(timeout);

        ProviderConfigProperty syncPassword = new ProviderConfigProperty();
        syncPassword.setName(CONFIG_SYNC_PASSWORD);
        syncPassword.setLabel("Sync Password to Keycloak");
        syncPassword.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        syncPassword.setHelpText("Đồng bộ password từ user input vào Keycloak sau khi verify thành công qua API");
        syncPassword.setDefaultValue("true");
        config.add(syncPassword);

        ProviderConfigProperty fallbackToKeycloak = new ProviderConfigProperty();
        fallbackToKeycloak.setName(CONFIG_FALLBACK_TO_KEYCLOAK);
        fallbackToKeycloak.setLabel("Fallback to Keycloak on API Error");
        fallbackToKeycloak.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        fallbackToKeycloak.setHelpText("Khi API lỗi (timeout, connection error), có fallback về Keycloak authentication không");
        fallbackToKeycloak.setDefaultValue("false");
        config.add(fallbackToKeycloak);

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