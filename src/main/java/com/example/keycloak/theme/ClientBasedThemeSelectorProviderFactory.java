package com.example.keycloak.theme;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.theme.ThemeSelectorProvider;
import org.keycloak.theme.ThemeSelectorProviderFactory;

import java.util.HashMap;
import java.util.Map;

public class ClientBasedThemeSelectorProviderFactory implements ThemeSelectorProviderFactory {

    private final Map<String, String> clientThemeMapping = new HashMap<>();

    @Override
    public ThemeSelectorProvider create(KeycloakSession session) {
        return new ClientBasedThemeSelectorProvider(session, clientThemeMapping);
    }

    @Override
    public void init(Config.Scope config) {
        String mappingConfig = config.get("clientThemeMapping");

        if (mappingConfig != null && !mappingConfig.isEmpty()) {
            String[] mappings = mappingConfig.split(",");
            for (String mapping : mappings) {
                String[] parts = mapping.split(":");
                if (parts.length == 2) {
                    clientThemeMapping.put(parts[0].trim(), parts[1].trim());
                }
            }
        }

        if (clientThemeMapping.isEmpty()) {
            clientThemeMapping.put("account-console", "account-theme");
            clientThemeMapping.put("admin-console", "admin-theme");
            clientThemeMapping.put("ccp-client-id", "theme-a");
            clientThemeMapping.put("ccp-client-id1", "theme-b");
        }
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
        clientThemeMapping.clear();
    }

    @Override
    public String getId() {
        return "client-based";
    }
}