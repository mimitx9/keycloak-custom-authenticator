package com.example.keycloak.ocb.auth;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class ExternalUserVerificationAuthenticatorFactory implements AuthenticatorFactory {
    public static final String CONFIG_API_URL = "apiUrl";
    public static final String CONFIG_API_USERNAME = "apiUsername";
    public static final String CONFIG_API_PASSWORD = "apiPassword";
    public static final String CONFIG_TARGET_CLIENT_ID = "targetClientId";
    public static final String PROVIDER_ID = "external-user-verification";
    private static final ExternalUserVerificationAuthenticator SINGLETON = new ExternalUserVerificationAuthenticator();

    @Override
    public String getDisplayType() {
        return "External User Verification";
    }

    @Override
    public String getReferenceCategory() {
        return "External API";
    }

    @Override
    public boolean isConfigurable() {
        return true;  // Quan trọng: phải trả về true để SPI có thể cấu hình
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
        return "Xác thực người dùng qua API bên ngoài và đồng bộ thông tin người dùng về Keycloak.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        List<ProviderConfigProperty> config = new ArrayList<>();

        // Cấu hình API URL
        ProviderConfigProperty apiUrl = new ProviderConfigProperty();
        apiUrl.setName(CONFIG_API_URL);
        apiUrl.setLabel("API URL");
        apiUrl.setType(ProviderConfigProperty.STRING_TYPE);
        apiUrl.setHelpText("URL đầy đủ của API bên ngoài để xác thực người dùng (ví dụ: http://localhost:8080/cb/callbacks/customer/authentication/verify)");
        config.add(apiUrl);

        // Cấu hình API Username
        ProviderConfigProperty apiUsername = new ProviderConfigProperty();
        apiUsername.setName(CONFIG_API_USERNAME);
        apiUsername.setLabel("API Username");
        apiUsername.setType(ProviderConfigProperty.STRING_TYPE);
        apiUsername.setHelpText("Username cho Basic Authentication với API bên ngoài");
        config.add(apiUsername);

        // Cấu hình API Password - sử dụng kiểu PASSWORD để che giấu
        ProviderConfigProperty apiPassword = new ProviderConfigProperty();
        apiPassword.setName(CONFIG_API_PASSWORD);
        apiPassword.setLabel("API Password");
        apiPassword.setType(ProviderConfigProperty.PASSWORD);
        apiPassword.setHelpText("Password cho Basic Authentication với API bên ngoài");
        config.add(apiPassword);

        // Cấu hình Target Client ID
        ProviderConfigProperty targetClientId = new ProviderConfigProperty();
        targetClientId.setName(CONFIG_TARGET_CLIENT_ID);
        targetClientId.setLabel("Target Client ID");
        targetClientId.setType(ProviderConfigProperty.STRING_TYPE);
        targetClientId.setHelpText("Client ID mà sẽ áp dụng xác thực bên ngoài");
        targetClientId.setDefaultValue("ccp-client-id");  // Đã cập nhật theo log của bạn
        config.add(targetClientId);

        return config;
    }

    @Override
    public Authenticator create(KeycloakSession keycloakSession) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope scope) {
        // Không cần khởi tạo gì
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
        // Không cần khởi tạo sau
    }

    @Override
    public void close() {
        // Không cần giải phóng tài nguyên
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}