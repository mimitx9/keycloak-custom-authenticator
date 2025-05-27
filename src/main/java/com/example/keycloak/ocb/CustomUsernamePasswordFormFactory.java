package com.example.keycloak.ocb;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

/**
 * Factory để tạo CustomUsernamePasswordForm
 */
public class CustomUsernamePasswordFormFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "custom-username-password-form";
    private static final CustomUsernamePasswordForm SINGLETON = new CustomUsernamePasswordForm();

    @Override
    public String getDisplayType() {
        return "Custom Username Password Form";
    }

    @Override
    public String getReferenceCategory() {
        return "custom-form";
    }

    @Override
    public boolean isConfigurable() {
        return false; // Không cần cấu hình
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
        return "Thu thập username và password nhưng không kiểm tra xác thực trên Keycloak. " +
                "Được thiết kế để sử dụng với các authenticator bên ngoài.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null; // Không có thuộc tính cấu hình
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
        // Không cần khởi tạo
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
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