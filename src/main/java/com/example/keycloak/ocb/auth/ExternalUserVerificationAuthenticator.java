package com.example.keycloak.ocb.auth;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Map;

public class ExternalUserVerificationAuthenticator implements Authenticator {
    private static final Logger logger = Logger.getLogger(ExternalUserVerificationAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        // Retrieve information from authentication session
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        authSession.removeAuthNote("EXT_VERIFY_CHALLENGE_STATE");

        String username = authSession.getAuthNote("EXTERNAL_USERNAME");
        String password = authSession.getAuthNote("EXTERNAL_PASSWORD");

        if (username == null || password == null) {
            logger.error("Missing username or password in authentication session");
            // Display error and return to login form
            Response challengeResponse = context.form()
                    .setError("Please enter complete login information.")
                    .createLoginUsernamePassword();
            context.challenge(challengeResponse);
            return;
        }

        logger.infof("Username: %s, Password available: %s", username, password != null ? "Yes" : "No");

        // Get configuration
        ExternalVerificationConfig config = ExternalVerificationConfig.getConfig(context);

        // Check client ID
        String currentClientId = context.getAuthenticationSession().getClient().getClientId();
        String configuredClientId = config.getTargetClientId();

        // Check if current client is the configured client
        if (configuredClientId == null || configuredClientId.isEmpty() ||
                !configuredClientId.equals(currentClientId)) {
            logger.infof("Client %s is not configured for external authentication.", currentClientId);
            Response challengeResponse = context.form()
                    .setError("System is not properly configured. Please contact administrator.")
                    .createLoginUsernamePassword();
            context.challenge(challengeResponse);
            return;
        }

        // Call API for authentication
        try {
            ExternalApiClient apiClient = new ExternalApiClient(
                    config.getApiUrl(),
                    config.getApiUsername(),
                    config.getApiPassword()
            );

            Map<String, String> userInfo = apiClient.verifyUser(username, password);

            if (userInfo == null) {
                authSession.setAuthNote("EXT_VERIFY_CHALLENGE_STATE", "true");
                logger.warnf("Authentication failed for user %s with external API", username);

                // Create response with custom error message
                Response challengeResponse = context.form()
                        .setError("Incorrect username or password. Please try again.")
                        .createLoginUsernamePassword();

                context.challenge(challengeResponse);
                return;
            }

            logger.infof("Authentication successful for user %s with external API", username);

            // Authentication successful, check if user exists in Keycloak
            UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), username);

            if (user == null) {
                // User doesn't exist, create new
                logger.info("Creating new user in Keycloak");
                user = createUserInKeycloak(context, userInfo);
                if (user == null) {
                    logger.error("Unable to create user in Keycloak");
                    Response challengeResponse = context.form()
                            .setError("Unable to create user account. Please contact administrator.")
                            .createLoginUsernamePassword();
                    context.challenge(challengeResponse);
                    return;
                }
            } else {
                // User exists, update information
                logger.info("Updating existing user in Keycloak");
                updateUserInKeycloak(user, userInfo);
            }

            // Remove sensitive information from authentication session
            authSession.removeAuthNote("EXTERNAL_PASSWORD");

            // Set authenticated user and complete authentication flow
            context.setUser(user);
            context.success();
            logger.info("Authentication successful");
        } catch (Exception e) {
            logger.error("Error during external authentication", e);
            Response challengeResponse = context.form()
                    .setError("An error occurred during authentication. Please try again later.")
                    .createLoginUsernamePassword();
            context.challenge(challengeResponse);
        }
    }

    private UserModel createUserInKeycloak(AuthenticationFlowContext context, Map<String, String> userInfo) {
        try {
            RealmModel realm = context.getRealm();
            UserModel newUser = context.getSession().users().addUser(realm, userInfo.get("username"));
            newUser.setEnabled(true);
            newUser.setEmail(userInfo.get("email"));

            String fullName = userInfo.get("fullName");
            if (fullName != null && !fullName.isEmpty()) {
                String[] names = fullName.split(" ", 2);
                if (names.length > 0) {
                    newUser.setFirstName(names[0]);
                    if (names.length > 1) {
                        newUser.setLastName(names[1]);
                    }
                }
            }

            // Set user attributes
            newUser.setSingleAttribute("mobile", userInfo.get("mobile"));
            newUser.setSingleAttribute("customerNumber", userInfo.get("customerNumber"));
            // Đánh dấu user này đã được xác thực bởi hệ thống bên ngoài
            newUser.setSingleAttribute("externalVerified", "true");

            logger.infof("Created user in Keycloak: %s", newUser.getUsername());
            return newUser;
        } catch (Exception e) {
            logger.error("Error creating user in Keycloak", e);
            return null;
        }
    }

    private void updateUserInKeycloak(UserModel user, Map<String, String> userInfo) {
        try {
            // Cập nhật thông tin cơ bản
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

            // Cập nhật attributes
            user.setSingleAttribute("mobile", userInfo.get("mobile"));
            user.setSingleAttribute("customerNumber", userInfo.get("customerNumber"));
            user.setSingleAttribute("externalVerified", "true");
            user.setSingleAttribute("lastExternalVerification", String.valueOf(System.currentTimeMillis()));

            logger.infof("Updated user in Keycloak: %s", user.getUsername());
        } catch (Exception e) {
            logger.error("Error updating user in Keycloak", e);
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        logger.info("Starting action method in ExternalUserVerificationAuthenticator");

        // Đọc từ form trước khi đọc từ session
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String formUsername = formData.getFirst("username");
        String formPassword = formData.getFirst("password");

        if (formUsername != null && !formUsername.isEmpty() && formPassword != null && !formPassword.isEmpty()) {
            logger.infof("Found credentials in form - username: %s", formUsername);

            // Cập nhật session với dữ liệu form mới
            AuthenticationSessionModel authSession = context.getAuthenticationSession();
            authSession.setAuthNote("EXTERNAL_USERNAME", formUsername);
            authSession.setAuthNote("EXTERNAL_PASSWORD", formPassword);
        }

        // Lấy thông tin từ session (đã cập nhật nếu có dữ liệu form)
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String username = authSession.getAuthNote("EXTERNAL_USERNAME");
        String password = authSession.getAuthNote("EXTERNAL_PASSWORD");

        logger.infof("Using credentials from session - username: %s", username);

        // Gọi authenticate để xử lý xác thực
        authenticate(context);
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
        // No required actions needed
    }

    @Override
    public void close() {
        // No resources to clean up
    }
}