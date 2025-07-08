package com.example.keycloak.ocb.auth;

public class OtpResponse {
    private final String code;
    private final String message;
    private final boolean success;

    public OtpResponse(String code, String message, boolean success) {
        this.code = code;
        this.message = message;
        this.success = success;
    }

    public String getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }

    public boolean isSuccess() {
        return success;
    }

    // Static factory methods
    public static OtpResponse success(String code, String message) {
        return new OtpResponse(code, message, true);
    }

    public static OtpResponse error(String code, String message) {
        return new OtpResponse(code, message, false);
    }

    public static OtpResponse timeout() {
        return new OtpResponse("TIMEOUT", "Request timeout", false);
    }

    public static OtpResponse connectionError() {
        return new OtpResponse("CONNECTION_ERROR", "Connection error", false);
    }

    @Override
    public String toString() {
        return "OtpResponse{" +
                "code='" + code + '\'' +
                ", message='" + message + '\'' +
                ", success=" + success +
                '}';
    }
}