package com.example.keycloak.corp;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;


public class CccdPhoneAuthenticator implements Authenticator {

    public static final String CCCD_FIELD = "cccd";
    public static final String PHONE_FIELD = "phone";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        // Hiển thị form để nhập CCCD và số điện thoại
        Response challenge = context.form()
                .createForm("cccd-phone-form.ftl");
        context.challenge(challenge);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String cccdInput = formData.getFirst(CCCD_FIELD);
        String phoneInput = formData.getFirst(PHONE_FIELD);

        // Kiểm tra nếu trống
        if (cccdInput == null || cccdInput.isEmpty() || phoneInput == null || phoneInput.isEmpty()) {
            Response challenge = context.form()
                    .setError("Vui lòng nhập đầy đủ CCCD và số điện thoại")
                    .createForm("cccd-phone-form.ftl");
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            return;
        }

        // Tìm kiếm người dùng theo CCCD và số điện thoại
        UserModel user = findUserByCccdAndPhone(context, cccdInput, phoneInput);

        if (user == null) {
            // Không tìm thấy người dùng khớp
            Response challenge = context.form()
                    .setError("Thông tin không chính xác")
                    .createForm("cccd-phone-form.ftl");
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            return;
        }

        // Đã tìm thấy người dùng, lưu vào context để sử dụng ở bước tiếp theo
        context.setUser(user);

        // Lưu số điện thoại vào session để sử dụng cho OTP sau này
        context.getAuthenticationSession().setAuthNote("phone_number", phoneInput);

        // Chuyển qua bước tiếp theo
        context.success();
    }

    private UserModel findUserByCccdAndPhone(AuthenticationFlowContext context, String cccd, String phone) {
        RealmModel realm = context.getRealm();
        UserProvider users = context.getSession().users();

        // Tìm user có thuộc tính CCCD và Phone Number khớp với input
        return users.searchForUserByUserAttributeStream(realm, "cccd", cccd)
                .filter(user -> phone.equals(user.getFirstAttribute("phoneNumber")))
                .findFirst()
                .orElse(null);
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
        // Không cần thiết lập required actions
    }

    @Override
    public void close() {
        // Không cần cleanup
    }
}