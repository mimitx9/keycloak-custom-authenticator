package com.example.keycloak.ocb.authenticate.model;

import java.util.Map;

public class ApiResponse {
    private final String code;
    private final String message;
    private final Map<String, String> userInfo;
    private final boolean success;

    public ApiResponse(String code, String message, Map<String, String> userInfo, boolean success) {
        this.code = code;
        this.message = message;
        this.userInfo = userInfo;
        this.success = success;
    }

    public String getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }

    public Map<String, String> getUserInfo() {
        return userInfo;
    }

    public boolean isSuccess() {
        return success;
    }

    public static ApiResponse success(Map<String, String> userInfo) {
        return new ApiResponse("00", "Success", userInfo, true);
    }

    public static ApiResponse error(String code, String message) {
        return new ApiResponse(code, message, null, false);
    }

    public static ApiResponse timeout() {
        return new ApiResponse("TIMEOUT", "Request timeout", null, false);
    }

    public static ApiResponse connectionError() {
        return new ApiResponse("CONNECTION_ERROR", "Connection error", null, false);
    }
}