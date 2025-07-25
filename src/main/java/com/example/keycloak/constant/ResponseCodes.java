package com.example.keycloak.constant;

/**
 * Contains all response codes (error and success) used in custom authenticators
 */
public final class ResponseCodes {

    private ResponseCodes() {
    }

    // User và Field validation
    public static final String USER_NOT_FOUND = "USER_NOT_FOUND";
    public static final String FIELD_REQUIRED = "FIELD_REQUIRED";
    public static final String NETWORK_ERROR = "NETWORK_ERROR";
    public static final String INTERNAL_ERROR = "INTERNAL_ERROR";

    // Login related
    public static final String PHONE_INVALID_FORMAT = "PHONE_INVALID_FORMAT";
    public static final String LOGIN_FAILED = "LOGIN_FAILED";
    public static final String LOGIN_FAILED_LOCKED = "LOGIN_FAILED_LOCKED";
    public static final String LOGIN_ACCOUNT_LOCKED = "LOGIN_ACCOUNT_LOCKED";
    public static final String LOGIN_SUCCESS = "LOGIN_SUCCESS";

    // OTP related - Basic
    public static final String OTP_SENT = "OTP_SENT";
    public static final String OTP_SEND_FAILED = "OTP_SEND_FAILED";
    public static final String OTP_SEND_ERROR = "OTP_SEND_ERROR";
    public static final String OTP_INVALID_FORMAT = "OTP_INVALID_FORMAT";
    public static final String OTP_INVALID = "OTP_INVALID";
    public static final String OTP_VERIFY_ERROR = "OTP_VERIFY_ERROR";
    public static final String OTP_SUCCESS = "OTP_SUCCESS";

    // OTP related - Lockout và Limits
    public static final String OTP_INVALID_LOCKED = "OTP_INVALID_LOCKED";
    public static final String OTP_ACCOUNT_LOCKED = "OTP_ACCOUNT_LOCKED";
    public static final String OTP_RESEND_COOLDOWN = "OTP_RESEND_COOLDOWN";
    public static final String OTP_REQUEST_LIMIT_EXCEEDED = "OTP_REQUEST_LIMIT_EXCEEDED";

    // Account Lockout General
    public static final String ACCOUNT_TEMPORARILY_LOCKED = "ACCOUNT_TEMPORARILY_LOCKED";
    public static final String LOCKOUT_EXPIRED = "LOCKOUT_EXPIRED";
    public static final String MAX_ATTEMPTS_REACHED = "MAX_ATTEMPTS_REACHED";

    public static final String OTP_EXPIRED = "OTP_EXPIRED";
    public static final String SESSION_EXPIRED = "SESSION_EXPIRED";
    public static final String INVALID_SESSION = "INVALID_SESSION";
    public static final String SESSION_TIMEOUT = "SESSION_TIMEOUT";

    // Configuration và Service
    public static final String CONFIGURATION_ERROR = "CONFIGURATION_ERROR";
    public static final String MISSING_CONFIGURATION = "MISSING_CONFIGURATION";
    public static final String SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE";
}