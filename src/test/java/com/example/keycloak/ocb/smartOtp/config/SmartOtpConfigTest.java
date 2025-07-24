package com.example.keycloak.ocb.smartOtp.config;

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
class SmartOtpConfigTest {

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
        configMap.put("otpUrl", "https://test-otp-api.com");
        configMap.put("otpApiKey", "test_api_key");
        configMap.put("timeout", "15");
        configMap.put("maxOtpPerDay", "50");
        configMap.put("notificationTitle", "Custom Title");
        when(configModel.getConfig()).thenReturn(configMap);

        SmartOtpConfig config = SmartOtpConfig.getConfig(context);

        assertEquals("https://test-otp-api.com", config.getOtpUrl());
        assertEquals("test_api_key", config.getOtpApiKey());
        assertEquals(15, config.getTimeout());
        assertEquals(50, config.getMaxOtpPerDay());
        assertEquals("Custom Title", config.getNotificationTitle());
        assertTrue(config.isValid());
    }

    @Test
    void testGetConfig_DefaultValues() {
        Map<String, String> configMap = new HashMap<>();
        configMap.put("otpUrl", "https://test-otp-api.com");
        configMap.put("otpApiKey", "test_api_key");
        when(configModel.getConfig()).thenReturn(configMap);

        SmartOtpConfig config = SmartOtpConfig.getConfig(context);

        assertEquals("1|CCP|Login|0", config.getTransactionData());
        assertEquals("Xác thực đăng nhập", config.getNotificationTitle());
        assertEquals(100, config.getMaxOtpPerDay());
        assertEquals(10, config.getTimeout());
    }
}