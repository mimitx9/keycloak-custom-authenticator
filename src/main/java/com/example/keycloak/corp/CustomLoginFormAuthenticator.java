package com.example.keycloak.corp;

import com.example.keycloak.constant.ResponseCodes;
import com.example.keycloak.util.ResponseMessageHandler;
import com.example.keycloak.util.RetryLogicHandler;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.jboss.logging.Logger;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import java.util.HashMap;
import java.util.Map;

public class CustomLoginFormAuthenticator implements Authenticator {
    private static final Logger logger = Logger.getLogger(CustomLoginFormAuthenticator.class);
    private static final String LEGAL_ID_PARAM = "legalId";
    private static final String PHONE_PARAM = "phone";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        Response challengeResponse = challenge(context, null, null);
        context.challenge(challengeResponse);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        if (formData.containsKey("cancel")) {
            context.resetFlow();
            return;
        }

        if (!validateForm(context, formData)) {
            return;
        }

        String legalId = formData.getFirst(LEGAL_ID_PARAM);
        String phone = formData.getFirst(PHONE_PARAM);
        String username = legalId + "_" + phone;

        UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), username);

        if (user == null) {
            logger.warnf("User not found: %s", username);
            context.getEvent().user((String) null);
            context.getEvent().error(Errors.USER_NOT_FOUND);
            Response challengeResponse = challenge(context, ResponseCodes.USER_NOT_FOUND, null);
            context.challenge(challengeResponse);
            return;
        }

        context.setUser(user);

        RetryLogicHandler.LockoutStatus lockoutStatus =
                RetryLogicHandler.checkLockoutStatus(context, username, "login");

        if (lockoutStatus.isLocked()) {
            Map<String, Object> errorData = ResponseMessageHandler.createLoginLockoutResponse(
                    lockoutStatus.getLockedAt(),
                    lockoutStatus.getLockDuration(),
                    lockoutStatus.getFailedAttempts()
            );

            Response challengeResponse = challenge(context, ResponseCodes.LOGIN_ACCOUNT_LOCKED, errorData);
            context.challenge(challengeResponse);
            return;
        }

        RetryLogicHandler.resetFailedAttempts(context, username, "login");

        context.getAuthenticationSession().setAuthNote("legalId", legalId);
        context.getAuthenticationSession().setAuthNote("phone", phone);
        context.getAuthenticationSession().setAuthNote("identifier", username);

        logger.infof("User %s passed login validation", username);
        context.success();
    }

    private boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        String legalId = formData.getFirst(LEGAL_ID_PARAM);
        String phone = formData.getFirst(PHONE_PARAM);

        if (legalId == null || legalId.trim().isEmpty()) {
            Response challengeResponse = challenge(context, ResponseCodes.FIELD_REQUIRED, null);
            context.challenge(challengeResponse);
            return false;
        }

        if (phone == null || phone.trim().isEmpty()) {
            Response challengeResponse = challenge(context, ResponseCodes.FIELD_REQUIRED, null);
            context.challenge(challengeResponse);
            return false;
        }
        return true;
    }

    protected Response challenge(AuthenticationFlowContext context, String responseCode, Map<String, Object> responseData) {
        LoginFormsProvider forms = context.form();
        if (responseCode != null) {
            forms.setAttribute("responseCode", responseCode);
            if (responseData != null) {
                forms.setAttribute("responseData", responseData);
            }
        }

        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        if (config != null && config.getConfig() != null) {
            String unlockUrl = config.getConfig().get("unlockUrl");
            if (unlockUrl != null) {
                forms.setAttribute("unlockUrl", unlockUrl);
            }
        }

        return forms.createForm("custom-login-form.ftl");
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // No required actions
    }

    @Override
    public void close() {
        // No cleanup needed
    }
}