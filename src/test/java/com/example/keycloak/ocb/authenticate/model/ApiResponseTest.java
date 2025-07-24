package com.example.keycloak.ocb.authenticate.model;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ApiResponseTest {

    @Test
    void testSuccessResponse() {
        // Given
        Map<String, String> userInfo = new HashMap<>();
        userInfo.put("customerNumber", "123456789");
        userInfo.put("username", "testuser");

        // When
        ApiResponse response = ApiResponse.success(userInfo);

        // Then
        assertTrue(response.isSuccess());
        assertEquals("00", response.getCode());
        assertEquals("Success", response.getMessage());
        assertEquals(userInfo, response.getUserInfo());
    }

    @Test
    void testErrorResponse() {
        // When
        ApiResponse response = ApiResponse.error("01", "Invalid credentials");

        // Then
        assertFalse(response.isSuccess());
        assertEquals("01", response.getCode());
        assertEquals("Invalid credentials", response.getMessage());
        assertNull(response.getUserInfo());
    }

    @Test
    void testTimeoutResponse() {
        // When
        ApiResponse response = ApiResponse.timeout();

        // Then
        assertFalse(response.isSuccess());
        assertEquals("TIMEOUT", response.getCode());
        assertEquals("Request timeout", response.getMessage());
        assertNull(response.getUserInfo());
    }

    @Test
    void testConnectionErrorResponse() {
        // When
        ApiResponse response = ApiResponse.connectionError();

        // Then
        assertFalse(response.isSuccess());
        assertEquals("CONNECTION_ERROR", response.getCode());
        assertEquals("Connection error", response.getMessage());
        assertNull(response.getUserInfo());
    }
}