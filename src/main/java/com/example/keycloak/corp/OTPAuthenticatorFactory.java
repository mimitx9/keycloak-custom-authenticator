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

                new ProviderConfigProperty(MAX_OTP_ATTEMPTS, "Max OTP Attempts",
                        "Maximum number of OTP verification attempts before lockout", ProviderConfigProperty.STRING_TYPE,
                        "3"),

                new ProviderConfigProperty(OTP_LOCKOUT_DURATION_MINUTES, "OTP Lockout Duration (minutes)",
                        "Duration to lock OTP attempts after max failures", ProviderConfigProperty.STRING_TYPE,
                        "15"),

                new ProviderConfigProperty(OTP_RESEND_COOLDOWN_SECONDS, "OTP Resend Cooldown (seconds)",
                        "Cooldown period between OTP resend requests", ProviderConfigProperty.STRING_TYPE,
                        "30"),
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