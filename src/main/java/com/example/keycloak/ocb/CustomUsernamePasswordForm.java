package com.example.keycloak.ocb;

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import jakarta.ws.rs.core.MultivaluedMap;

public class CustomUsernamePasswordForm implements Authenticator {
    private static final Logger logger = Logger.getLogger(CustomUsernamePasswordForm.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        logger.info("Starting authenticate method");

        Response response = context.form().createLoginUsernamePassword();
        context.challenge(response);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        logger.info("Starting action method in CustomUsernamePasswordForm");

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        if (formData.containsKey("cancel")) {
            context.cancelLogin();
            return;
        }

        String username = formData.getFirst("username");
        String password = formData.getFirst("password");

        // QUAN TRỌNG: Clear tất cả auth notes của bước verification
        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        // Clear tất cả notes từ bước verification trước
        authSession.removeAuthNote("EXTERNAL_USERNAME");
        authSession.removeAuthNote("EXTERNAL_PASSWORD");
        authSession.removeAuthNote("EXT_VERIFY_CHALLENGE_STATE");

        // THÊM: Clear các notes verification
        authSession.removeAuthNote("EXTERNAL_VERIFICATION_COMPLETED");
        authSession.removeAuthNote("VERIFIED_USERNAME");
        authSession.removeAuthNote("CUSTOMER_NUMBER");
        authSession.removeAuthNote("USER_INFO_JSON");
        authSession.removeAuthNote("EXT_API_RESPONSE_CODE");
        authSession.removeAuthNote("EXT_API_RESPONSE_MESSAGE");
        authSession.removeAuthNote("EXT_API_SUCCESS");

        if (username == null || username.isEmpty()) {
            Response response = context.form()
                    .setError("Vui lòng nhập tên đăng nhập.")
                    .createLoginUsernamePassword();
            context.challenge(response);
            return;
        }

        if (password == null || password.isEmpty()) {
            Response response = context.form()
                    .setError("Vui lòng nhập mật khẩu.")
                    .createLoginUsernamePassword();
            context.challenge(response);
            return;
        }

        // Lưu thông tin mới
        authSession.setAuthNote("EXTERNAL_USERNAME", username);
        authSession.setAuthNote("EXTERNAL_PASSWORD", password);

        context.success();
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
    }

    @Override
    public void close() {
    }
}