package com.example.keycloak.ocb;

import com.example.keycloak.ocb.authenticate.model.ApiResponse;
import com.example.keycloak.ocb.smartOtp.model.OtpResponse;
import com.example.keycloak.ocb.authenticate.config.OcbVerificationConfig;
import com.example.keycloak.ocb.smartOtp.config.SmartOtpConfig;
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
class WorkingUnitTests {

    @Mock
    private AuthenticationFlowContext context;

    @Mock
    private AuthenticatorConfigModel configModel;

    @Test
    void testApiResponse_Success() {
        Map<String, String> userInfo = new HashMap<>();
        userInfo.put("customerNumber", "123456789");
        userInfo.put("username", "testuser");
        userInfo.put("fullName", "Test User");
        userInfo.put("email", "test@example.com");
        userInfo.put("mobile", "0123456789");

        ApiResponse response = ApiResponse.success(userInfo);

        assertTrue(response.isSuccess());
        assertEquals("00", response.getCode());
        assertEquals("Success", response.getMessage());
        assertNotNull(response.getUserInfo());
        assertEquals("123456789", response.getUserInfo().get("customerNumber"));
        assertEquals("testuser", response.getUserInfo().get("username"));
    }

    @Test
    void testApiResponse_Error() {
        ApiResponse response = ApiResponse.error("01", "Invalid credentials");

        assertFalse(response.isSuccess());
        assertEquals("01", response.getCode());
        assertEquals("Invalid credentials", response.getMessage());
        assertNull(response.getUserInfo());
    }

    @Test
    void testApiResponse_Timeout() {
        ApiResponse response = ApiResponse.timeout();

        assertFalse(response.isSuccess());
        assertEquals("TIMEOUT", response.getCode());
        assertEquals("Request timeout", response.getMessage());
        assertNull(response.getUserInfo());
    }

    @Test
    void testApiResponse_ConnectionError() {
        ApiResponse response = ApiResponse.connectionError();

        assertFalse(response.isSuccess());
        assertEquals("CONNECTION_ERROR", response.getCode());
        assertEquals("Connection error", response.getMessage());
        assertNull(response.getUserInfo());
    }

    @Test
    void testOtpResponse_Success() {
        OtpResponse response = OtpResponse.success("00", "OTP sent successfully");

        assertTrue(response.isSuccess());
        assertEquals("00", response.getCode());
        assertEquals("OTP sent successfully", response.getMessage());
    }

    @Test
    void testOtpResponse_Error() {
        OtpResponse response = OtpResponse.error("01", "Invalid OTP");

        assertFalse(response.isSuccess());
        assertEquals("01", response.getCode());
        assertEquals("Invalid OTP", response.getMessage());
    }

    @Test
    void testOtpResponse_Timeout() {
        OtpResponse response = OtpResponse.timeout();

        assertFalse(response.isSuccess());
        assertEquals("TIMEOUT", response.getCode());
        assertEquals("Request timeout", response.getMessage());
    }

    @Test
    void testOtpResponse_ConnectionError() {
        OtpResponse response = OtpResponse.connectionError();

        assertFalse(response.isSuccess());
        assertEquals("CONNECTION_ERROR", response.getCode());
        assertEquals("Connection error", response.getMessage());
    }

    @Test
    void testOtpResponse_ToString() {
        OtpResponse response = OtpResponse.success("00", "Success");
        String result = response.toString();

        assertTrue(result.contains("code='00'"));
        assertTrue(result.contains("message='Success'"));
        assertTrue(result.contains("success=true"));
    }

    @Test
    void testOcbVerificationConfig_ValidConfig() {
        when(context.getAuthenticatorConfig()).thenReturn(configModel);

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
    void testOcbVerificationConfig_EmptyConfig() {
        when(context.getAuthenticatorConfig()).thenReturn(configModel);
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
    void testOcbVerificationConfig_InvalidTimeout() {
        when(context.getAuthenticatorConfig()).thenReturn(configModel);

        Map<String, String> configMap = new HashMap<>();
        configMap.put("apiUrl", "https://test-api.com");
        configMap.put("apiUsername", "test_user");
        configMap.put("apiPassword", "test_pass");
        configMap.put("timeout", "invalid");
        when(configModel.getConfig()).thenReturn(configMap);

        OcbVerificationConfig config = OcbVerificationConfig.getConfig(context);

        assertEquals(10, config.getTimeout()); // should use default
    }

    @Test
    void testSmartOtpConfig_ValidConfig() {
        when(context.getAuthenticatorConfig()).thenReturn(configModel);

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
    void testSmartOtpConfig_DefaultValues() {
        when(context.getAuthenticatorConfig()).thenReturn(configModel);

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

    @Test
    void testSmartOtpConfig_InvalidConfig() {
        when(context.getAuthenticatorConfig()).thenReturn(configModel);
        when(configModel.getConfig()).thenReturn(null);

        SmartOtpConfig config = SmartOtpConfig.getConfig(context);

        assertFalse(config.isValid());
        assertEquals("", config.getOtpUrl());
        assertEquals("", config.getOtpApiKey());
    }

    @Test
    void testStringProcessing() {
        String testString = "test@example.com";

        assertTrue(testString.contains("@"));
        assertTrue(testString.endsWith(".com"));
        assertEquals("TEST@EXAMPLE.COM", testString.toUpperCase());
        assertEquals(16, testString.length());
    }

    @Test
    void testMapOperations() {
        Map<String, String> testMap = new HashMap<>();
        testMap.put("key1", "value1");
        testMap.put("key2", "value2");

        assertEquals(2, testMap.size());
        assertTrue(testMap.containsKey("key1"));
        assertEquals("value1", testMap.get("key1"));
        assertNull(testMap.get("nonexistent"));
    }
}