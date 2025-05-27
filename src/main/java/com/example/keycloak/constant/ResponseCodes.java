package com.example.keycloak.constant;

/**
 * Contains all response codes (error and success) used in custom authenticators
 */
public final class ResponseCodes {

    private ResponseCodes() {
    }

    public static final String FIELD_REQUIRED = "FIELD_REQUIRED";
    public static final String NETWORK_ERROR = "NETWORK_ERROR";
    public static final String INTERNAL_ERROR = "INTERNAL_ERROR";

    public static final String PHONE_INVALID_FORMAT = "PHONE_INVALID_FORMAT";
    public static final String LOGIN_FAILED = "LOGIN_FAILED";
    public static final String LOGIN_FAILED_LOCKED = "LOGIN_FAILED_LOCKED";
    public static final String LOGIN_ACCOUNT_LOCKED = "LOGIN_ACCOUNT_LOCKED";
    public static final String LOGIN_SUCCESS = "LOGIN_SUCCESS";

    public static final String OTP_SENT = "OTP_SENT";
    public static final String OTP_SEND_FAILED = "OTP_SEND_FAILED";
    public static final String OTP_SEND_ERROR = "OTP_SEND_ERROR";
    public static final String OTP_RESEND_COOLDOWN = "OTP_RESEND_COOLDOWN";
    public static final String OTP_INVALID_FORMAT = "OTP_INVALID_FORMAT";
    public static final String OTP_INVALID = "OTP_INVALID";
    public static final String OTP_INVALID_LOCKED = "OTP_INVALID_LOCKED";
    public static final String OTP_ACCOUNT_LOCKED = "OTP_ACCOUNT_LOCKED";
    public static final String OTP_VERIFY_ERROR = "OTP_VERIFY_ERROR";
    public static final String OTP_SUCCESS = "OTP_SUCCESS";

    public static final String ACCOUNT_TEMPORARILY_LOCKED = "ACCOUNT_TEMPORARILY_LOCKED";
    public static final String LOCKOUT_EXPIRED = "LOCKOUT_EXPIRED";
    public static final String MAX_ATTEMPTS_REACHED = "MAX_ATTEMPTS_REACHED";
    public static final String SESSION_EXPIRED = "SESSION_EXPIRED";
    public static final String INVALID_SESSION = "INVALID_SESSION";
    public static final String SESSION_TIMEOUT = "SESSION_TIMEOUT";

    public static final String CONFIGURATION_ERROR = "CONFIGURATION_ERROR";
    public static final String MISSING_CONFIGURATION = "MISSING_CONFIGURATION";
    public static final String SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE";
}