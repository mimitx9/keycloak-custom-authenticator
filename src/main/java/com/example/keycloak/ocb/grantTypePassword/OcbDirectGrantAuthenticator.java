package com.example.keycloak.ocb.grantTypePassword;

import com.example.keycloak.ocb.authenticate.client.OcbClient;
import com.example.keycloak.ocb.authenticate.model.ApiResponse;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.directgrant.AbstractDirectGrantAuthenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.services.managers.AuthenticationManager;

import java.util.Arrays;
import java.util.Map;

public class OcbDirectGrantAuthenticator implements Authenticator {
    private static final Logger logger = Logger.getLogger(OcbDirectGrantAuthenticator.class);

    @Override
    public void action(AuthenticationFlowContext context) {
        logger.debug("Action method called - not implemented for Direct Grant flow");
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {

        MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();
        String username = inputData.getFirst(AuthenticationManager.FORM_USERNAME);
        String password = inputData.getFirst(CredentialRepresentation.PASSWORD);

        if (username == null || username.trim().isEmpty()) {
            logger.warn("Username is missing in direct grant request");
            context.getEvent().error("invalid_user_credentials");
            context.failure(AuthenticationFlowError.INVALID_USER,
                    Response.status(Response.Status.UNAUTHORIZED)
                            .header("WWW-Authenticate", "Basic realm=\"" + context.getRealm().getDisplayName() + "\"")
                            .build());
            return;
        }

        if (password == null || password.trim().isEmpty()) {
            logger.warn("Password is missing in direct grant request");
            context.getEvent().error("invalid_user_credentials");
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
                    Response.status(Response.Status.UNAUTHORIZED)
                            .header("WWW-Authenticate", "Basic realm=\"" + context.getRealm().getDisplayName() + "\"")
                            .build());
            return;
        }

        username = username.trim();
        password = password.trim();

        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        if (config == null) {
            logger.warn("No authenticator configuration found, falling back to Keycloak authentication");
            performKeycloakAuthentication(context, username, password);
            return;
        }

        Map<String, String> configMap = config.getConfig();
        boolean enableExternalAuth = Boolean.parseBoolean(
                configMap.getOrDefault(OcbDirectGrantAuthenticatorFactory.CONFIG_ENABLE_EXTERNAL_AUTH, "false"));

        logger.infof("External authentication enabled: %s", enableExternalAuth);

        if (!enableExternalAuth) {
            logger.info("External authentication is disabled, using Keycloak authentication");
            performKeycloakAuthentication(context, username, password);
            return;
        }
        String apiUrl = configMap.get(OcbDirectGrantAuthenticatorFactory.CONFIG_API_URL);
        String apiUsername = configMap.get(OcbDirectGrantAuthenticatorFactory.CONFIG_API_USERNAME);
        String apiPassword = configMap.get(OcbDirectGrantAuthenticatorFactory.CONFIG_API_PASSWORD);
        String timeoutStr = configMap.getOrDefault(OcbDirectGrantAuthenticatorFactory.CONFIG_TIMEOUT, "30");
        boolean syncPassword = Boolean.parseBoolean(
                configMap.getOrDefault(OcbDirectGrantAuthenticatorFactory.CONFIG_SYNC_PASSWORD, "true"));
        boolean fallbackToKeycloak = Boolean.parseBoolean(
                configMap.getOrDefault(OcbDirectGrantAuthenticatorFactory.CONFIG_FALLBACK_TO_KEYCLOAK, "false"));

        if (apiUrl == null || apiUrl.trim().isEmpty() ||
                apiUsername == null || apiUsername.trim().isEmpty() ||
                apiPassword == null || apiPassword.trim().isEmpty()) {
            logger.error("OCB API configuration is incomplete");
            if (fallbackToKeycloak) {
                logger.info("Falling back to Keycloak authentication due to incomplete config");
                performKeycloakAuthentication(context, username, password);
                return;
            } else {
                context.failure(AuthenticationFlowError.CLIENT_CREDENTIALS_SETUP_REQUIRED);
                return;
            }
        }

        int timeout;
        try {
            timeout = Integer.parseInt(timeoutStr);
        } catch (NumberFormatException e) {
            logger.warnf("Invalid timeout value '%s', using default 30 seconds", timeoutStr);
            timeout = 30;
        }

        performExternalAuthentication(context, username, password, apiUrl, apiUsername, apiPassword,
                timeout, syncPassword, fallbackToKeycloak);
    }

    private void performExternalAuthentication(AuthenticationFlowContext context, String username, String password,
                                               String apiUrl, String apiUsername, String apiPassword, int timeout,
                                               boolean syncPassword, boolean fallbackToKeycloak) {
        logger.info("=== Performing External API Authentication ===");

        try {
            logger.info("Creating OCB API client for authentication");
            OcbClient apiClient = new OcbClient(apiUrl, apiUsername, apiPassword, timeout);

            logger.infof("Calling external API to verify user: %s", username);
            ApiResponse userVerifyResponse = apiClient.verifyUser(username, password);

            logger.infof("External API response - Code: %s, Message: %s, Success: %s",
                    userVerifyResponse.getCode(),
                    userVerifyResponse.getMessage(),
                    userVerifyResponse.isSuccess());

            if (!userVerifyResponse.isSuccess()) {
                logger.warnf("External API authentication failed for user %s: %s",
                        username, userVerifyResponse.getMessage());
                if (fallbackToKeycloak) {
                    logger.info("API error detected, falling back to Keycloak authentication");
                    performKeycloakAuthentication(context, username, password);
                    return;
                }

                context.getEvent().error("invalid_user_credentials");
                context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
                        Response.status(Response.Status.UNAUTHORIZED)
                                .header("WWW-Authenticate", "Basic realm=\"" + context.getRealm().getDisplayName() + "\"")
                                .build());
                return;
            }
            Map<String, String> userInfo = userVerifyResponse.getUserInfo();
            if (userInfo == null) {
                logger.warn("No user info returned from successful API call");
                context.failure(AuthenticationFlowError.UNKNOWN_USER);
                return;
            }

            logger.info("External API authentication successful, creating/updating user");
            UserModel user = findOrCreateUser(context, username, userInfo, syncPassword ? password : null);
            if (user == null) {
                logger.error("Failed to find or create user in Keycloak");
                context.failure(AuthenticationFlowError.UNKNOWN_USER);
                return;
            }
            context.setUser(user);
            context.success();
            logger.infof("External authentication successful for user: %s", username);

        } catch (Exception e) {
            logger.error("Unexpected error during external API authentication", e);

            if (fallbackToKeycloak) {
                logger.info("Exception occurred, falling back to Keycloak authentication");
                performKeycloakAuthentication(context, username, password);
            } else {
                context.failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR);
            }
        }
    }

    private void performKeycloakAuthentication(AuthenticationFlowContext context, String username, String password) {
        logger.info("=== Performing Keycloak Authentication ===");

        try {
            RealmModel realm = context.getRealm();
            UserModel user = context.getSession().users().getUserByUsername(realm, username);

            if (user == null) {
                logger.warnf("User %s not found in Keycloak", username);
                context.getEvent().error("user_not_found");
                context.failure(AuthenticationFlowError.UNKNOWN_USER,
                        Response.status(Response.Status.UNAUTHORIZED)
                                .header("WWW-Authenticate", "Basic realm=\"" + realm.getDisplayName() + "\"")
                                .build());
                return;
            }

            if (!user.isEnabled()) {
                logger.warnf("User %s is disabled", username);
                context.getEvent().error("user_disabled");
                context.failure(AuthenticationFlowError.USER_DISABLED,
                        Response.status(Response.Status.UNAUTHORIZED)
                                .header("WWW-Authenticate", "Basic realm=\"" + realm.getDisplayName() + "\"")
                                .build());
                return;
            }

            UserCredentialModel passwordCredential = UserCredentialModel.password(password);
            if (!user.credentialManager().isValid(passwordCredential)) {
                logger.warnf("Invalid password for user %s", username);
                context.getEvent().error("invalid_user_credentials");
                context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
                        Response.status(Response.Status.UNAUTHORIZED)
                                .header("WWW-Authenticate", "Basic realm=\"" + realm.getDisplayName() + "\"")
                                .build());
                return;
            }

            context.setUser(user);
            context.success();
            logger.infof("Keycloak authentication successful for user: %s", username);

        } catch (Exception e) {
            logger.error("Error during Keycloak authentication", e);
            context.failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR);
        }
    }

    private UserModel findOrCreateUser(AuthenticationFlowContext context, String username,
                                       Map<String, String> userInfo, String passwordToSync) {
        logger.info("=== Finding or creating user in Keycloak ===");

        try {
            RealmModel realm = context.getRealm();
            UserModel user = context.getSession().users().getUserByUsername(realm, username);

            if (user == null) {
                logger.infof("Creating new user in Keycloak: %s", username);
                user = context.getSession().users().addUser(realm, username);
                if (user != null) {
                    user.setEnabled(true);
                    updateUserAttributes(user, userInfo);

                    // Sync password if requested
                    if (passwordToSync != null) {
                        syncPasswordToKeycloak(context, user, passwordToSync);
                    }

                    logger.infof("User created successfully: %s", username);
                }
            } else {
                logger.infof("Found existing user in Keycloak: %s", username);
                updateUserAttributes(user, userInfo);
                if (passwordToSync != null) {
                    syncPasswordToKeycloak(context, user, passwordToSync);
                }
            }

            return user;

        } catch (Exception e) {
            logger.error("Error finding or creating user in Keycloak", e);
            return null;
        }
    }

    private void syncPasswordToKeycloak(AuthenticationFlowContext context, UserModel user, String password) {
        try {
            logger.infof("Syncing password to Keycloak for user: %s", user.getUsername());

            // Set password using UserModel
            UserCredentialModel passwordCredential = UserCredentialModel.password(password);
            user.credentialManager().updateCredential(passwordCredential);

            logger.infof("Password synced successfully for user: %s", user.getUsername());

        } catch (Exception e) {
            logger.error("Error syncing password to Keycloak", e);
        }
    }

    private void updateUserAttributes(UserModel user, Map<String, String> userInfo) {
        try {
            logger.info("Updating user attributes from API response");

            // Set basic user info
            String email = userInfo.get("email");
            if (email != null && !email.isEmpty()) {
                user.setEmail(email);
                user.setEmailVerified(true);
            }

            String fullName = userInfo.get("fullName");
            if (fullName != null && !fullName.isEmpty()) {
                // Split full name into first and last name
                String[] names = fullName.split(" ", 2);
                user.setFirstName(names[0]);
                if (names.length > 1) {
                    user.setLastName(names[1]);
                }
            }

            // Set custom attributes
            user.setSingleAttribute("customerNumber", userInfo.get("customerNumber"));
            user.setSingleAttribute("mobile", userInfo.get("mobile"));
            user.setSingleAttribute("externalVerified", "true");
            user.setSingleAttribute("lastExternalVerification", String.valueOf(System.currentTimeMillis()));
            user.setSingleAttribute("authenticationSource", "OCB_API");

            logger.infof("User attributes updated successfully for: %s", user.getUsername());

        } catch (Exception e) {
            logger.error("Error updating user attributes", e);
        }
    }

    @Override
    public boolean requiresUser() {
        return false; // We handle user creation/lookup ourselves
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true; // Always available when configured
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // No required actions needed
    }

    @Override
    public void close() {
        // No cleanup needed
    }
}