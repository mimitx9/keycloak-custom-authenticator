package com.example.keycloak.ocb.smartOtp.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class OtpResponseTest {

    @Test
    void testSuccessResponse() {
        // When
        OtpResponse response = OtpResponse.success("00", "OTP sent successfully");

        // Then
        assertTrue(response.isSuccess());
        assertEquals("00", response.getCode());
        assertEquals("OTP sent successfully", response.getMessage());
    }

    @Test
    void testErrorResponse() {
        // When
        OtpResponse response = OtpResponse.error("01", "Invalid OTP");

        // Then
        assertFalse(response.isSuccess());
        assertEquals("01", response.getCode());
        assertEquals("Invalid OTP", response.getMessage());
    }

    @Test
    void testTimeoutResponse() {
        // When
        OtpResponse response = OtpResponse.timeout();

        // Then
        assertFalse(response.isSuccess());
        assertEquals("TIMEOUT", response.getCode());
        assertEquals("Request timeout", response.getMessage());
    }

    @Test
    void testConnectionErrorResponse() {
        // When
        OtpResponse response = OtpResponse.connectionError();

        // Then
        assertFalse(response.isSuccess());
        assertEquals("CONNECTION_ERROR", response.getCode());
        assertEquals("Connection error", response.getMessage());
    }

    @Test
    void testToString() {
        // Given
        OtpResponse response = OtpResponse.success("00", "Success");

        // When
        String result = response.toString();

        // Then
        assertTrue(result.contains("code='00'"));
        assertTrue(result.contains("message='Success'"));
        assertTrue(result.contains("success=true"));
    }
}