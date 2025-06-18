package com.example.keycloak.corp;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.List;

public class OTPAuthenticatorFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {

    public static final String PROVIDER_ID = "otp-authenticator";

    public static final String OTP_ASSIGN_URL = "otpAssignUrl";
    public static final String OTP_VERIFY_URL = "otpVerifyUrl";
    public static final String OTP_REQUEST_ID_PREFIX = "otpRequestIdPrefix";
    public static final String OTP_SESSION_PREFIX = "otpSessionPrefix";
    public static final String OTP_BR_REQUEST_ID = "otpBrRequestId";
    public static final String OTP_REQUESTOR = "otpRequestor";
    public static final String OTP_TYPE = "otpType";
    public static final String OTP_LENGTH = "otpLength";
    public static final String OTP_METHOD = "otpMethod";
    public static final String CONNECTION_TIMEOUT = "connectionTimeout";
    public static final String MAX_OTP_ATTEMPTS = "maxOtpAttempts";
    public static final String OTP_LOCKOUT_DURATION_MINUTES = "otpLockoutDurationMinutes";
    public static final String OTP_RESEND_COOLDOWN_SECONDS = "otpResendCooldownSeconds";

    public static final String OTP_VALIDITY_SECONDS = "otpValiditySeconds";
    public static final String AUTO_RESET_PERIOD_MINUTES = "autoResetPeriodMinutes";
    public static final String OTP_REQUEST_RESET_PERIOD_MINUTES = "otpRequestResetPeriodMinutes";
    public static final String MAX_OTP_REQUESTS_PER_PERIOD = "maxOtpRequestsPerPeriod";

    public static final String LOCKOUT_DURATION_3 = "lockoutDuration3";
    public static final String LOCKOUT_DURATION_4 = "lockoutDuration4";
    public static final String LOCKOUT_DURATION_5 = "lockoutDuration5";
    public static final String LOCKOUT_DURATION_6_PLUS = "lockoutDuration6Plus";

    @Override
    public String getDisplayType() {
        return "OTP Bizconnect Authenticator";
    }

    @Override
    public String getReferenceCategory() {
        return "OTP";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[]{
                AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.ALTERNATIVE,
                AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Send and verify OTP using external API service - BizConnect";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Arrays.asList(
                // API Configuration
                new ProviderConfigProperty(OTP_ASSIGN_URL, "OTP Assign URL",
                        "URL endpoint for sending OTP", ProviderConfigProperty.STRING_TYPE,
                        "http://10.37.16.153:7111/api/ibps/otp/assign"),

                new ProviderConfigProperty(OTP_VERIFY_URL, "OTP Verify URL",
                        "URL endpoint for verifying OTP", ProviderConfigProperty.STRING_TYPE,
                        "http://10.37.16.153:7111/api/ibps/otp/verify"),

                new ProviderConfigProperty(OTP_REQUEST_ID_PREFIX, "Request ID Prefix",
                        "Prefix for request ID generation", ProviderConfigProperty.STRING_TYPE,
                        "DMS"),

                new ProviderConfigProperty(OTP_SESSION_PREFIX, "OTP Session Prefix",
                        "Prefix for OTP session generation", ProviderConfigProperty.STRING_TYPE,
                        "VPB"),

                new ProviderConfigProperty(OTP_BR_REQUEST_ID, "BR Request ID",
                        "Business Request ID for OTP", ProviderConfigProperty.STRING_TYPE,
                        "VN0010242"),

                new ProviderConfigProperty(OTP_REQUESTOR, "OTP Requestor",
                        "System identifier requesting OTP", ProviderConfigProperty.STRING_TYPE,
                        "ECM"),

                new ProviderConfigProperty(OTP_TYPE, "OTP Type",
                        "Type of OTP service", ProviderConfigProperty.STRING_TYPE,
                        "ECM"),

                new ProviderConfigProperty(OTP_LENGTH, "OTP Length",
                        "Length of generated OTP", ProviderConfigProperty.STRING_TYPE,
                        "6"),

                new ProviderConfigProperty(OTP_METHOD, "OTP Method",
                        "Method for OTP delivery (1=SMS)", ProviderConfigProperty.STRING_TYPE,
                        "1"),

                new ProviderConfigProperty(CONNECTION_TIMEOUT, "Connection Timeout (seconds)",
                        "HTTP connection timeout in seconds", ProviderConfigProperty.STRING_TYPE,
                        "10"),

                // Timing Configuration
                new ProviderConfigProperty(OTP_VALIDITY_SECONDS, "OTP Validity (seconds)",
                        "OTP validity duration in seconds", ProviderConfigProperty.STRING_TYPE,
                        "180"),

                new ProviderConfigProperty(OTP_RESEND_COOLDOWN_SECONDS, "OTP Resend Cooldown (seconds)",
                        "Cooldown period between OTP resend requests", ProviderConfigProperty.STRING_TYPE,
                        "30"),

                new ProviderConfigProperty(AUTO_RESET_PERIOD_MINUTES, "Auto Reset Period (minutes)",
                        "Auto reset failed attempts after X minutes", ProviderConfigProperty.STRING_TYPE,
                        "1440"),

                new ProviderConfigProperty(OTP_REQUEST_RESET_PERIOD_MINUTES, "OTP Request Reset Period (minutes)",
                        "Reset OTP request count after X minutes", ProviderConfigProperty.STRING_TYPE,
                        "60"),

                // Rate Limiting Configuration
                new ProviderConfigProperty(MAX_OTP_REQUESTS_PER_PERIOD, "Max OTP Requests per Period",
                        "Maximum number of OTP requests per reset period", ProviderConfigProperty.STRING_TYPE,
                        "5"),

                new ProviderConfigProperty(MAX_OTP_ATTEMPTS, "Max OTP Attempts",
                        "Maximum number of OTP verification attempts before lockout", ProviderConfigProperty.STRING_TYPE,
                        "3"),

                // Lockout Duration Configuration
                new ProviderConfigProperty(LOCKOUT_DURATION_3, "Lockout Duration 3rd Attempt (minutes)",
                        "Lockout duration after 3rd failed attempt", ProviderConfigProperty.STRING_TYPE,
                        "5"),

                new ProviderConfigProperty(LOCKOUT_DURATION_4, "Lockout Duration 4th Attempt (minutes)",
                        "Lockout duration after 4th failed attempt", ProviderConfigProperty.STRING_TYPE,
                        "10"),

                new ProviderConfigProperty(LOCKOUT_DURATION_5, "Lockout Duration 5th Attempt (minutes)",
                        "Lockout duration after 5th failed attempt", ProviderConfigProperty.STRING_TYPE,
                        "20"),

                new ProviderConfigProperty(LOCKOUT_DURATION_6_PLUS, "Lockout Duration 6+ Attempts (minutes)",
                        "Lockout duration after 6th and subsequent failed attempts", ProviderConfigProperty.STRING_TYPE,
                        "1440"),

                // Legacy config for backward compatibility
                new ProviderConfigProperty(OTP_LOCKOUT_DURATION_MINUTES, "OTP Lockout Duration (minutes) [Legacy]",
                        "Duration to lock OTP attempts after max failures - Legacy config", ProviderConfigProperty.STRING_TYPE,
                        "15"),

                // Other Configuration
                new ProviderConfigProperty("unlockUrl", "Unlock URL",
                        "URL for OTP unlock system", ProviderConfigProperty.STRING_TYPE,
                        "http://10.37.0.197/doanh-nghiep/unlock-account")
        );
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new OTPAuthenticator();
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}