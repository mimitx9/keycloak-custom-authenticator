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

        // Lấy thông tin xác thực từ form mới nhất
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        if (formData.containsKey("cancel")) {
            context.cancelLogin();
            return;
        }

        String username = formData.getFirst("username");
        String password = formData.getFirst("password");

        logger.infof("CustomUsernamePasswordForm received credentials - username: %s, password provided: %b",
                username, password != null && !password.isEmpty());

        // Xóa dữ liệu cũ trong session
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        authSession.removeAuthNote("EXTERNAL_USERNAME");
        authSession.removeAuthNote("EXTERNAL_PASSWORD");
        authSession.removeAuthNote("EXT_VERIFY_CHALLENGE_STATE");  // Đảm bảo xóa trạng thái challenge

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

        // Lưu thông tin mới vào session
        logger.infof("Storing credentials in session - username: %s", username);
        authSession.setAuthNote("EXTERNAL_USERNAME", username);
        authSession.setAuthNote("EXTERNAL_PASSWORD", password);

        // Chuyển đến bước tiếp theo
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