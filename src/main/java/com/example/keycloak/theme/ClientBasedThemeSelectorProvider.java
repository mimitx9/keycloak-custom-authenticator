package com.example.keycloak.theme;

import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;
import org.keycloak.theme.ThemeSelectorProvider;

import java.util.Map;

public class ClientBasedThemeSelectorProvider implements ThemeSelectorProvider {

    private final KeycloakSession session;
    private final Map<String, String> clientThemeMapping;

    public ClientBasedThemeSelectorProvider(KeycloakSession session, Map<String, String> clientThemeMapping) {
        this.session = session;
        this.clientThemeMapping = clientThemeMapping;
    }

    @Override
    public String getThemeName(Theme.Type type) {
        if (type != Theme.Type.LOGIN && type != Theme.Type.ACCOUNT) {
            return null;
        }

        try {
            String clientId = getClientId();
            if (clientId != null && clientThemeMapping.containsKey(clientId)) {
                return clientThemeMapping.get(clientId);
            }
        } catch (Exception e) {
            // Xử lý ngoại lệ nếu có
            System.err.println("Error in ClientBasedThemeSelectorProvider: " + e.getMessage());
        }

        return null;
    }

    private String getClientId() {
        // Thử lấy client ID từ authentication session
        AuthenticationSessionModel authSession = session.getContext().getAuthenticationSession();
        if (authSession != null && authSession.getClient() != null) {
            return authSession.getClient().getClientId();
        }

        // Thử lấy client ID từ context
        ClientModel client = session.getContext().getClient();
        if (client != null) {
            return client.getClientId();
        }

        return null;
    }

    @Override
    public void close() {
        // Không cần làm gì khi đóng
    }
}