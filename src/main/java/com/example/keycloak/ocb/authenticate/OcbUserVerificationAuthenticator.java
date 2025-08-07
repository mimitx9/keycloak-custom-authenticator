package com.example.keycloak.ocb.authenticate;

import com.example.keycloak.ocb.authenticate.client.OcbClient;
import com.example.keycloak.ocb.authenticate.config.OcbVerificationConfig;
import com.example.keycloak.ocb.authenticate.model.ApiResponse;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Map;

public class OcbUserVerificationAuthenticator implements Authenticator {
    private static final Logger logger = Logger.getLogger(OcbUserVerificationAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        logger.info("=== Starting OCB User Verification ===");
        showLoginForm(context, null);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        logger.info("=== Processing OCB verification action ===");

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String username = formData.getFirst("username");
        String password = formData.getFirst("password");

        logger.infof("Form submission - Username: %s, Password provided: %s",
                username, password != null && !password.isEmpty());

        if (username == null || username.trim().isEmpty() ||
                password == null || password.trim().isEmpty()) {
            logger.warn("Username or password is empty");
            showLoginForm(context, "Vui lòng nhập đầy đủ tên đăng nhập và mật khẩu");
            return;
        }

        username = username.trim();
        password = password.trim();

        verifyUserWithOcb(context, username, password);
    }

    private void verifyUserWithOcb(AuthenticationFlowContext context, String username, String password) {
        logger.infof("=== Verifying user with OCB API: %s ===", username);

        OcbVerificationConfig config = OcbVerificationConfig.getConfig(context);

        if (!config.isValid()) {
            logger.error("OCB verification config is invalid");
            context.failure(AuthenticationFlowError.CLIENT_CREDENTIALS_SETUP_REQUIRED);
            return;
        }

        try {
            OcbClient apiClient = new OcbClient(
                    config.getApiUrl(),
                    config.getApiUsername(),
                    config.getApiPassword(),
                    config.getTimeout()
            );

            logger.infof("Calling OCB API to verify user: %s", username);
            ApiResponse userVerifyResponse = apiClient.verifyUser(username, password);

            logger.infof("OCB API response - Code: %s, Message: %s, Success: %s",
                    userVerifyResponse.getCode(),
                    userVerifyResponse.getMessage(),
                    userVerifyResponse.isSuccess());

            if (!userVerifyResponse.isSuccess()) {
                handleVerificationError(context, userVerifyResponse);
                return;
            }

            // Verify thành công, tạo/cập nhật user
            Map<String, String> userInfo = userVerifyResponse.getUserInfo();

            if (userInfo == null || userInfo.isEmpty()) {
                logger.error("No user info returned from successful API call");
                showLoginForm(context, "Lỗi không xác định từ hệ thống");
                return;
            }

            String customerNumber = userInfo.get("customerNumber");
            if (customerNumber == null || customerNumber.isEmpty()) {
                logger.error("No customerNumber found in user verification response");
                showLoginForm(context, "Thông tin khách hàng không hợp lệ");
                return;
            }

            logger.infof("User verification successful - CustomerNumber: %s, Email: %s",
                    customerNumber, userInfo.get("email"));

            UserModel user = createOrUpdateUser(context, username, userInfo);
            if (user == null) {
                logger.error("Failed to create/update user in Keycloak");
                showLoginForm(context, "Lỗi tạo thông tin người dùng");
                return;
            }

            // Set user context và hoàn thành authentication
            context.setUser(user);
            context.success();

            logger.infof("OCB verification completed successfully for user: %s", username);

        } catch (Exception e) {
            logger.error("Unexpected error during OCB verification", e);
            showLoginForm(context, "Lỗi hệ thống. Vui lòng thử lại.");
        }
    }

    private UserModel createOrUpdateUser(AuthenticationFlowContext context, String username, Map<String, String> userInfo) {
        logger.infof("=== Creating/updating user in Keycloak: %s ===", username);

        try {
            UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), username);

            if (user == null) {
                logger.infof("Creating new user: %s", username);
                user = context.getSession().users().addUser(context.getRealm(), username);
            } else {
                logger.infof("Updating existing user: %s", username);
            }

            // Set user attributes
            user.setEnabled(true);
            user.setEmail(userInfo.get("email"));

            String fullName = userInfo.get("fullName");
            if (fullName != null && !fullName.isEmpty()) {
                String[] names = fullName.split(" ", 2);
                if (names.length > 0) {
                    user.setFirstName(names[0]);
                    if (names.length > 1) {
                        user.setLastName(names[1]);
                    }
                }
            }

            user.setSingleAttribute("mobile", userInfo.get("mobile"));
            user.setSingleAttribute("customerNumber", userInfo.get("customerNumber"));
            user.setSingleAttribute("externalVerified", "true");
            user.setSingleAttribute("lastExternalVerification", String.valueOf(System.currentTimeMillis()));

            logger.infof("User created/updated successfully: %s (Customer: %s)",
                    username, userInfo.get("customerNumber"));
            return user;

        } catch (Exception e) {
            logger.error("Error creating/updating user in Keycloak", e);
            return null;
        }
    }

    private void handleVerificationError(AuthenticationFlowContext context, ApiResponse userVerifyResponse) {
        logger.warnf("OCB verification failed. Code: %s, Message: %s",
                userVerifyResponse.getCode(), userVerifyResponse.getMessage());

        String errorMessage = userVerifyResponse.getMessage();
        if (errorMessage == null || errorMessage.isEmpty()) {
            errorMessage = "Thông tin đăng nhập không chính xác";
        }
        showLoginForm(context, errorMessage);
    }

    private void showLoginForm(AuthenticationFlowContext context, String message) {
        logger.info("Showing OCB verification login form");

        LoginFormsProvider form = context.form();

        if (message != null && !message.isEmpty()) {
            logger.infof("Showing form with message: %s", message);
            form.setError(message);
        }

        Response challengeResponse = form.createLoginUsernamePassword();
        context.challenge(challengeResponse);
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