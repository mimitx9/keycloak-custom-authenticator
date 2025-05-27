package com.example.keycloak.corp;

import com.example.keycloak.constant.ResponseCodes;
import com.example.keycloak.util.RetryLogicHandler;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
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

        // Create identifier for retry logic
        String identifier = legalId + "_" + phone;

        // Check lockout status before attempting login
        RetryLogicHandler.LockoutStatus lockoutStatus =
                RetryLogicHandler.checkLockoutStatus(context, identifier, "login");

        if (lockoutStatus.isLocked()) {
            Map<String, Object> errorData = new HashMap<>();
            errorData.put("identifier", maskIdentifier(identifier));
            errorData.put("remainingLockoutMs", lockoutStatus.getRemainingLockoutMs());
            errorData.put("failedAttempts", lockoutStatus.getFailedAttempts());

            Response challengeResponse = challenge(context, ResponseCodes.LOGIN_ACCOUNT_LOCKED, errorData);
            context.challenge(challengeResponse);
            return;
        }

        String username = legalId + "_" + phone;

        UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), username);

        if (user == null) {
            logger.warnf("User not found: %s", username);
            RetryLogicHandler.LockoutResult lockoutResult =
                    RetryLogicHandler.recordFailedAttempt(context, identifier, "login");

            context.getEvent().user((String) null);
            context.getEvent().error(Errors.USER_NOT_FOUND);

            Map<String, Object> errorData = new HashMap<>();
            errorData.put("attemptCount", lockoutResult.getAttemptCount());
            errorData.put("maxAttempts", lockoutResult.getMaxAttempts());
            errorData.put("isLocked", lockoutResult.isLocked());
            errorData.put("identifier", maskIdentifier(identifier));

            if (lockoutResult.isLocked()) {
                errorData.put("lockoutDurationMinutes", lockoutResult.getLockoutDurationMinutes());
                errorData.put("lockoutUntil", lockoutResult.getLockoutUntil());
            }

            String errorCode = lockoutResult.isLocked() ? ResponseCodes.LOGIN_FAILED_LOCKED : ResponseCodes.LOGIN_FAILED;
            Response challengeResponse = challenge(context, errorCode, errorData);
            context.challenge(challengeResponse);
            return;
        }

        RetryLogicHandler.resetFailedAttempts(context, identifier, "login");

        context.setUser(user);
        context.getAuthenticationSession().setAuthNote("legalId", legalId);
        context.getAuthenticationSession().setAuthNote("phone", phone);
        context.getAuthenticationSession().setAuthNote("identifier", identifier);

        logger.infof("User %s passed login validation", username);
        context.success();
    }

    private boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        String legalId = formData.getFirst(LEGAL_ID_PARAM);
        String phone = formData.getFirst(PHONE_PARAM);

        if (legalId == null || legalId.trim().isEmpty()) {
            Map<String, Object> errorData = new HashMap<>();
            errorData.put("field", "legalId");
            errorData.put("fieldName", "Legal ID");
            Response challengeResponse = challenge(context, ResponseCodes.FIELD_REQUIRED, errorData);
            context.challenge(challengeResponse);
            return false;
        }

        if (phone == null || phone.trim().isEmpty()) {
            Map<String, Object> errorData = new HashMap<>();
            errorData.put("field", "phone");
            errorData.put("fieldName", "Số điện thoại");
            Response challengeResponse = challenge(context, ResponseCodes.FIELD_REQUIRED, errorData);
            context.challenge(challengeResponse);
            return false;
        }
        return true;
    }

    private String maskIdentifier(String identifier) {
        if (identifier == null || identifier.length() < 6) {
            return identifier;
        }
        String[] parts = identifier.split("_");
        if (parts.length == 2) {
            String legalId = parts[0].length() > 3 ?
                    parts[0].substring(0, 3) + "***" : parts[0];
            String phone = parts[1].length() > 6 ?
                    parts[1].substring(0, 3) + "****" + parts[1].substring(parts[1].length() - 3) : parts[1];
            return legalId + "_" + phone;
        }
        return identifier.substring(0, 3) + "***";
    }

    protected Response challenge(AuthenticationFlowContext context, String responseCode, Map<String, Object> responseData) {
        LoginFormsProvider forms = context.form();
        if (responseCode != null) {
            forms.setAttribute("responseCode", responseCode);
            if (responseData != null) {
                forms.setAttribute("responseData", responseData);
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