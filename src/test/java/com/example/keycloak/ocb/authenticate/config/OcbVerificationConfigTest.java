package com.example.keycloak.ocb.authenticate.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OcbVerificationConfigTest {

    @Mock
    private AuthenticationFlowContext context;

    @Mock
    private AuthenticatorConfigModel configModel;

    @BeforeEach
    void setUp() {
        when(context.getAuthenticatorConfig()).thenReturn(configModel);
    }

    @Test
    void testGetConfig_ValidConfig() {
        Map<String, String> configMap = new HashMap<>();
        configMap.put("apiUrl", "https://test-api.com");
        configMap.put("apiUsername", "test_user");
        configMap.put("apiPassword", "test_pass");
        configMap.put("timeout", "15");
        configMap.put("isLastStep", "true");
        when(configModel.getConfig()).thenReturn(configMap);

        OcbVerificationConfig config = OcbVerificationConfig.getConfig(context);

        assertEquals("https://test-api.com", config.getApiUrl());
        assertEquals("test_user", config.getApiUsername());
        assertEquals("test_pass", config.getApiPassword());
        assertEquals(15, config.getTimeout());
        assertTrue(config.getIsLatStep());
        assertTrue(config.isValid());
    }

    @Test
    void testGetConfig_EmptyConfig() {
        when(configModel.getConfig()).thenReturn(null);

        OcbVerificationConfig config = OcbVerificationConfig.getConfig(context);

        assertEquals("", config.getApiUrl());
        assertEquals("", config.getApiUsername());
        assertEquals("", config.getApiPassword());
        assertEquals(10, config.getTimeout()); // default
        assertFalse(config.getIsLatStep()); // default
        assertFalse(config.isValid());
    }

    @Test
    void testGetConfig_InvalidTimeout() {
        Map<String, String> configMap = new HashMap<>();
        configMap.put("apiUrl", "https://test-api.com");
        configMap.put("apiUsername", "test_user");
        configMap.put("apiPassword", "test_pass");
        configMap.put("timeout", "invalid");
        when(configModel.getConfig()).thenReturn(configMap);

        OcbVerificationConfig config = OcbVerificationConfig.getConfig(context);

        assertEquals(10, config.getTimeout());
    }
}