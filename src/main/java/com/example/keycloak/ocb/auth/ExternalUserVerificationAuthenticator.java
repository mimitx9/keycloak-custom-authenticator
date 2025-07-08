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
import java.util.UUID;

public class ExternalUserVerificationAuthenticator implements Authenticator {
    private static final Logger logger = Logger.getLogger(ExternalUserVerificationAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        // Retrieve information from authentication session
        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        String username = authSession.getAuthNote("EXTERNAL_USERNAME");
        String password = authSession.getAuthNote("EXTERNAL_PASSWORD");
        String otpNumber = authSession.getAuthNote("EXTERNAL_OTP");
        String currentState = authSession.getAuthNote("AUTH_STATE");

        if (username == null || password == null) {
            logger.error("Missing username or password in authentication session");
            Response challengeResponse = context.form()
                    .setError("Please enter complete login information.")
                    .createLoginUsernamePassword();
            context.challenge(challengeResponse);
            return;
        }

        logger.infof("Username: %s, Password available: %s, OTP: %s, State: %s",
                username, "Yes", otpNumber != null ? "Yes" : "No", currentState);

        ExternalVerificationConfig config = ExternalVerificationConfig.getConfig(context);

        try {
            if (!"OTP_SENT".equals(currentState)) {
                ExternalApiClient apiClient = new ExternalApiClient(
                        config.getApiUrl(),
                        config.getApiUsername(),
                        config.getApiPassword(),
                        config.getTimeout()
                );

                ApiResponse userVerifyResponse = apiClient.verifyUser(username, password);

                if (!userVerifyResponse.isSuccess()) {
                    logger.warnf("User verification failed for %s. Code: %s, Message: %s",
                            username, userVerifyResponse.getCode(), userVerifyResponse.getMessage());

                    String errorMessage = userVerifyResponse.getMessage();
                    if (errorMessage == null || errorMessage.isEmpty()) {
                        errorMessage = "Authentication failed";
                    }

                    Response challengeResponse = context.form()
                            .setError(errorMessage)
                            .createLoginUsernamePassword();
                    context.challenge(challengeResponse);
                    return;
                }

                logger.infof("User verification successful for %s, creating OTP transaction", username);

                SmartOtpClient otpClient = new SmartOtpClient(
                        config.getOtpUrl(),
                        config.getOtpApiKey(),
                        config.getTimeout()
                );

                String transactionId = UUID.randomUUID().toString();
                String userId = "OCB_" + username;

                OtpResponse otpResponse = otpClient.createTransaction(
                        userId,
                        transactionId,
                        config.getTransactionData(),
                        config.getTransactionTypeId(),
                        config.getChallenge(),
                        config.getCallbackUrl(),
                        config.getOnline(),
                        config.getPush(),
                        config.getNotificationTitle(),
                        config.getNotificationBody(),
                        config.getEsignerTypeId(),
                        config.getChannelId()
                );

                authSession.setAuthNote("TRANSACTION_ID", transactionId);
                authSession.setAuthNote("USER_ID", userId);
                authSession.setAuthNote("AUTH_STATE", "OTP_SENT");

                Map<String, String> userInfo = userVerifyResponse.getUserInfo();
                if (userInfo != null) {
                    authSession.setAuthNote("USER_INFO_JSON",
                            new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(userInfo));
                }

                if (!otpResponse.isSuccess()) {
                    logger.warnf("OTP creation failed. Code: %s, Message: %s",
                            otpResponse.getCode(), otpResponse.getMessage());

                    String errorMessage = otpResponse.getMessage();
                    if (errorMessage == null || errorMessage.isEmpty()) {
                        errorMessage = "Failed to send OTP";
                    }

                    Response challengeResponse = context.form()
                            .setError(errorMessage)
                            .createLoginUsernamePassword();
                    context.challenge(challengeResponse);
                    return;
                }

                logger.info("OTP transaction created successfully, showing OTP input");
                Response otpChallengeResponse = context.form()
                        .setInfo("OTP has been sent. Please enter the OTP code.")
                        .setAttribute("showOtpField", true)
                        .setAttribute("username", username)
                        .createLoginUsernamePassword();
                context.challenge(otpChallengeResponse);
                return;

            } else {
                if (otpNumber == null || otpNumber.isEmpty()) {
                    logger.warn("OTP number is missing");
                    Response otpChallengeResponse = context.form()
                            .setError("Please enter the OTP code.")
                            .setAttribute("showOtpField", true)
                            .setAttribute("username", username)
                            .createLoginUsernamePassword();
                    context.challenge(otpChallengeResponse);
                    return;
                }

                String transactionId = authSession.getAuthNote("TRANSACTION_ID");
                String userId = authSession.getAuthNote("USER_ID");

                if (transactionId == null || userId == null) {
                    logger.error("Missing transaction ID or user ID in session");
                    Response challengeResponse = context.form()
                            .setError("Session expired. Please try again.")
                            .createLoginUsernamePassword();
                    context.challenge(challengeResponse);
                    return;
                }

                SmartOtpClient otpClient = new SmartOtpClient(
                        config.getOtpUrl(),
                        config.getOtpApiKey(),
                        config.getTimeout()
                );

                OtpResponse otpVerifyResponse = otpClient.verifyOtp(userId, otpNumber, transactionId);

                if (!otpVerifyResponse.isSuccess()) {
                    logger.warnf("OTP verification failed. Code: %s, Message: %s",
                            otpVerifyResponse.getCode(), otpVerifyResponse.getMessage());

                    String errorMessage = otpVerifyResponse.getMessage();
                    if (errorMessage == null || errorMessage.isEmpty()) {
                        errorMessage = "Invalid OTP code";
                    }

                    Response otpChallengeResponse = context.form()
                            .setError(errorMessage)
                            .setAttribute("showOtpField", true)
                            .setAttribute("username", username)
                            .createLoginUsernamePassword();
                    context.challenge(otpChallengeResponse);
                    return;
                }

                // Step 4: OTP verified successfully, complete authentication
                logger.infof("OTP verification successful for user %s", username);

                String userInfoJson = authSession.getAuthNote("USER_INFO_JSON");
                Map<String, String> userInfo = null;
                if (userInfoJson != null) {
                    userInfo = new com.fasterxml.jackson.databind.ObjectMapper()
                            .readValue(userInfoJson, Map.class);
                }

                if (userInfo == null || userInfo.isEmpty()) {
                    logger.error("No user info found in session");
                    Response challengeResponse = context.form()
                            .setError("Session expired. Please try again.")
                            .createLoginUsernamePassword();
                    context.challenge(challengeResponse);
                    return;
                }

                UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), username);

                if (user == null) {
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
                    logger.info("Updating existing user in Keycloak");
                    updateUserInKeycloak(user, userInfo);
                }

                authSession.removeAuthNote("EXTERNAL_PASSWORD");
                authSession.removeAuthNote("EXTERNAL_OTP");
                authSession.removeAuthNote("TRANSACTION_ID");
                authSession.removeAuthNote("USER_ID");
                authSession.removeAuthNote("AUTH_STATE");
                authSession.removeAuthNote("USER_INFO_JSON");

                context.setUser(user);
                context.success();
                logger.info("Authentication successful");
            }

        } catch (Exception e) {
            logger.error("Error during external authentication", e);

            // Clean up session on error
            authSession.removeAuthNote("AUTH_STATE");
            authSession.removeAuthNote("TRANSACTION_ID");
            authSession.removeAuthNote("USER_ID");
            authSession.removeAuthNote("USER_INFO_JSON");

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

            newUser.setSingleAttribute("mobile", userInfo.get("mobile"));
            newUser.setSingleAttribute("customerNumber", userInfo.get("customerNumber"));
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

            logger.infof("Updated user in Keycloak: %s", user.getUsername());
        } catch (Exception e) {
            logger.error("Error updating user in Keycloak", e);
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        logger.info("Starting action method in ExternalUserVerificationAuthenticator");

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String formUsername = formData.getFirst("username");
        String formPassword = formData.getFirst("password");
        String formOtp = formData.getFirst("otp");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String currentState = authSession.getAuthNote("AUTH_STATE");

        if ("OTP_SENT".equals(currentState)) {
            if (formOtp != null && !formOtp.isEmpty()) {
                logger.infof("Found OTP in form: %s", formOtp.substring(0, 2) + "***");
                authSession.setAuthNote("EXTERNAL_OTP", formOtp);
            }
        } else {
            if (formUsername != null && !formUsername.isEmpty() && formPassword != null && !formPassword.isEmpty()) {
                logger.infof("Found credentials in form - username: %s", formUsername);
                authSession.setAuthNote("EXTERNAL_USERNAME", formUsername);
                authSession.setAuthNote("EXTERNAL_PASSWORD", formPassword);
            }
        }

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
    }

    @Override
    public void close() {
    }
}