package com.example.keycloak.ocb.smartOtp.client;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for SmartOtpClient without external dependencies
 */
class SmartOtpClientUnitTest {

    private SmartOtpClient smartOtpClient;

    @BeforeEach
    void setUp() {
        smartOtpClient = new SmartOtpClient("https://dummy-otp-api.com", "dummy_api_key", 10);
    }

    @Test
    void testClientCreation() {
        assertNotNull(smartOtpClient);
    }

    @Test
    void testClientWithEmptyParameters() {
        assertDoesNotThrow(() -> {
            SmartOtpClient client = new SmartOtpClient("", "", 5);
            assertNotNull(client);
        });
    }

    @Test
    void testClientWithNullParameters() {
        assertDoesNotThrow(() -> {
            SmartOtpClient client = new SmartOtpClient(null, null, 0);
            assertNotNull(client);
        });
    }
}