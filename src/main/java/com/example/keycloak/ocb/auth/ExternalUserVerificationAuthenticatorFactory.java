package com.example.keycloak.ocb.auth;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class ExternalUserVerificationAuthenticatorFactory implements AuthenticatorFactory {
    public static final String CONFIG_API_URL = "apiUrl";
    public static final String CONFIG_API_USERNAME = "apiUsername";
    public static final String CONFIG_API_PASSWORD = "apiPassword";
    public static final String CONFIG_TIMEOUT = "timeout";

    public static final String CONFIG_OTP_URL = "otpUrl";
    public static final String CONFIG_OTP_API_KEY = "otpApiKey";
    public static final String CONFIG_TRANSACTION_DATA = "transactionData";
    public static final String CONFIG_TRANSACTION_TYPE_ID = "transactionTypeId";
    public static final String CONFIG_CHALLENGE = "challenge";
    public static final String CONFIG_CALLBACK_URL = "callbackUrl";
    public static final String CONFIG_ONLINE = "online";
    public static final String CONFIG_PUSH = "push";
    public static final String CONFIG_NOTIFICATION_TITLE = "notificationTitle";
    public static final String CONFIG_NOTIFICATION_BODY = "notificationBody";
    public static final String CONFIG_ESIGNER_TYPE_ID = "esignerTypeId";
    public static final String CONFIG_CHANNEL_ID = "channelId";
    public static final String CONFIG_MAX_OTP_PER_DAY = "maxOtpPerDay";
    public static final String PROVIDER_ID = "external-user-verification";
    private static final ExternalUserVerificationAuthenticator SINGLETON = new ExternalUserVerificationAuthenticator();

    @Override
    public String getDisplayType() {
        return "External User Verification with OTP";
    }

    @Override
    public String getReferenceCategory() {
        return "External API";
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
        return "Xác thực người dùng qua API của OCB và Smart OTP";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        List<ProviderConfigProperty> config = new ArrayList<>();

        ProviderConfigProperty apiUrl = new ProviderConfigProperty();
        apiUrl.setName(CONFIG_API_URL);
        apiUrl.setLabel("User Verification API URL");
        apiUrl.setType(ProviderConfigProperty.STRING_TYPE);
        apiUrl.setHelpText("URL của API xác thực user/password");
        config.add(apiUrl);

        ProviderConfigProperty apiUsername = new ProviderConfigProperty();
        apiUsername.setName(CONFIG_API_USERNAME);
        apiUsername.setLabel("API Username");
        apiUsername.setType(ProviderConfigProperty.STRING_TYPE);
        apiUsername.setHelpText("Username cho Basic Authentication");
        config.add(apiUsername);

        ProviderConfigProperty apiPassword = new ProviderConfigProperty();
        apiPassword.setName(CONFIG_API_PASSWORD);
        apiPassword.setLabel("API Password");
        apiPassword.setType(ProviderConfigProperty.PASSWORD);
        apiPassword.setHelpText("Password cho Basic Authentication");
        config.add(apiPassword);

        ProviderConfigProperty timeout = new ProviderConfigProperty();
        timeout.setName(CONFIG_TIMEOUT);
        timeout.setLabel("API Timeout (seconds)");
        timeout.setType(ProviderConfigProperty.STRING_TYPE);
        timeout.setHelpText("Timeout cho API call");
        timeout.setDefaultValue("10");
        config.add(timeout);

        ProviderConfigProperty otpUrl = new ProviderConfigProperty();
        otpUrl.setName(CONFIG_OTP_URL);
        otpUrl.setLabel("Smart OTP API Base URL");
        otpUrl.setType(ProviderConfigProperty.STRING_TYPE);
        otpUrl.setHelpText("Base URL của Smart OTP API");
        config.add(otpUrl);

        ProviderConfigProperty otpApiKey = new ProviderConfigProperty();
        otpApiKey.setName(CONFIG_OTP_API_KEY);
        otpApiKey.setLabel("Smart OTP API Key");
        otpApiKey.setType(ProviderConfigProperty.PASSWORD);
        otpApiKey.setHelpText("API Key cho Smart OTP");
        config.add(otpApiKey);

        // ========== Transaction Config ==========
        ProviderConfigProperty transactionData = new ProviderConfigProperty();
        transactionData.setName(CONFIG_TRANSACTION_DATA);
        transactionData.setLabel("Transaction Data");
        transactionData.setType(ProviderConfigProperty.STRING_TYPE);
        transactionData.setHelpText("Dữ liệu transaction");
        transactionData.setDefaultValue("1|CCP|Login|0");
        config.add(transactionData);

        ProviderConfigProperty transactionTypeId = new ProviderConfigProperty();
        transactionTypeId.setName(CONFIG_TRANSACTION_TYPE_ID);
        transactionTypeId.setLabel("Transaction Type ID");
        transactionTypeId.setType(ProviderConfigProperty.STRING_TYPE);
        transactionTypeId.setHelpText("ID transaction");
        transactionTypeId.setDefaultValue("1");
        config.add(transactionTypeId);

        ProviderConfigProperty challenge = new ProviderConfigProperty();
        challenge.setName(CONFIG_CHALLENGE);
        challenge.setLabel("Challenge");
        challenge.setType(ProviderConfigProperty.STRING_TYPE);
        challenge.setHelpText("Challenge string");
        challenge.setDefaultValue("");
        config.add(challenge);

        ProviderConfigProperty callbackUrl = new ProviderConfigProperty();
        callbackUrl.setName(CONFIG_CALLBACK_URL);
        callbackUrl.setLabel("Callback URL");
        callbackUrl.setType(ProviderConfigProperty.STRING_TYPE);
        callbackUrl.setHelpText("URL callback");
        callbackUrl.setDefaultValue("");
        config.add(callbackUrl);

        ProviderConfigProperty online = new ProviderConfigProperty();
        online.setName(CONFIG_ONLINE);
        online.setLabel("Online");
        online.setType(ProviderConfigProperty.STRING_TYPE);
        online.setHelpText("Online mode");
        online.setDefaultValue("0");
        config.add(online);

        ProviderConfigProperty push = new ProviderConfigProperty();
        push.setName(CONFIG_PUSH);
        push.setLabel("Push");
        push.setType(ProviderConfigProperty.STRING_TYPE);
        push.setHelpText("Push notification");
        push.setDefaultValue("1");
        config.add(push);

        ProviderConfigProperty notificationTitle = new ProviderConfigProperty();
        notificationTitle.setName(CONFIG_NOTIFICATION_TITLE);
        notificationTitle.setLabel("Notification Title");
        notificationTitle.setType(ProviderConfigProperty.STRING_TYPE);
        notificationTitle.setHelpText("Title");
        notificationTitle.setDefaultValue("Transaction confirmation");
        config.add(notificationTitle);

        ProviderConfigProperty notificationBody = new ProviderConfigProperty();
        notificationBody.setName(CONFIG_NOTIFICATION_BODY);
        notificationBody.setLabel("Notification Body");
        notificationBody.setType(ProviderConfigProperty.TEXT_TYPE);
        notificationBody.setHelpText("Content");
        notificationBody.setDefaultValue("You are making transaction on VPBank NEO. Please confirm the transaction.");
        config.add(notificationBody);

        ProviderConfigProperty esignerTypeId = new ProviderConfigProperty();
        esignerTypeId.setName(CONFIG_ESIGNER_TYPE_ID);
        esignerTypeId.setLabel("E-signer Type ID");
        esignerTypeId.setType(ProviderConfigProperty.STRING_TYPE);
        esignerTypeId.setHelpText("ID e-signer");
        esignerTypeId.setDefaultValue("6");
        config.add(esignerTypeId);

        ProviderConfigProperty channelId = new ProviderConfigProperty();
        channelId.setName(CONFIG_CHANNEL_ID);
        channelId.setLabel("Channel ID");
        channelId.setType(ProviderConfigProperty.STRING_TYPE);
        channelId.setHelpText("ID channel");
        channelId.setDefaultValue("1");
        config.add(channelId);

        return config;
    }

    @Override
    public Authenticator create(KeycloakSession keycloakSession) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope scope) {
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}