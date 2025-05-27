package com.example.keycloak.corp;

import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * TOTP Authenticator with account lockout functionality
 */
public class CustomTotpAuthenticator implements Authenticator {
    // Form page to use
    private static final String OTP_FORM_PAGE = "cccd-phone-form.ftl";

    // Constants for user attributes to track failed attempts and lockout
    private static final String FAILED_ATTEMPTS_KEY = "otp_failed_attempts";
    private static final String LOCKOUT_TIMESTAMP_KEY = "otp_lockout_timestamp";

    // Fixed OTP code for verification
    private static final String FIXED_OTP_CODE = "123456";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        if (user == null) {
            context.failure(AuthenticationFlowError.INVALID_USER);
            return;
        }

        // Check if the user is currently locked out
        if (isUserLocked(user)) {
            long remainingMinutes = calculateRemainingLockoutTime(user) / 60_000;

            // Prepare form data
            setupFormData(context);

            Response challenge = context.form()
                    .setError("Tài khoản bị khóa OTP. Vui lòng thử lại sau " + remainingMinutes + " phút.")
                    .createForm(OTP_FORM_PAGE);
            context.failureChallenge(AuthenticationFlowError.USER_TEMPORARILY_DISABLED, challenge);
            return;
        }

        // Setup form data
        setupFormData(context);

        // Show the OTP form
        Response challenge = context.form().createForm(OTP_FORM_PAGE);
        context.challenge(challenge);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        UserModel user = context.getUser();

        // Get the entered OTP from the form
        String enteredOtp = context.getHttpRequest().getDecodedFormParameters().getFirst("totp");

        // Verify the OTP
        if (FIXED_OTP_CODE.equals(enteredOtp)) {
            // OTP is correct, reset failed attempts and proceed
            resetFailedAttempts(user);
            context.success();
        } else {
            // OTP is incorrect, handle failed attempt
            handleFailedAttempt(context, user);

            // Setup form data for error response
            setupFormData(context);

            // Check if the account is now locked
            if (isUserLocked(user)) {
                long remainingMinutes = calculateRemainingLockoutTime(user) / 60_000;
                Response challenge = context.form()
                        .setError("Tài khoản bị khóa OTP. Vui lòng thử lại sau " + remainingMinutes + " phút.")
                        .createForm(OTP_FORM_PAGE);
                context.failureChallenge(AuthenticationFlowError.USER_TEMPORARILY_DISABLED, challenge);
            } else {
                // Not locked yet, show error message
                Response challenge = context.form()
                        .setError("Mã OTP không đúng. Vui lòng thử lại.")
                        .createForm(OTP_FORM_PAGE);
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            }
        }
    }

    private void setupFormData(AuthenticationFlowContext context) {
        // Setup basic data for the OTP form
        Map<String, Object> otpData = new HashMap<>();
        List<Map<String, String>> apps = new ArrayList<>();

        // Add application info
        Map<String, String> app = new HashMap<>();
        app.put("name", "Google Authenticator");
        app.put("helpText", "Nhập mã OTP để đăng nhập");
        apps.add(app);

        otpData.put("supportedApplications", apps);
        otpData.put("mode", "manual");

        // Set template attributes
        context.form().setAttribute("totp", otpData);
        context.form().setAttribute("otpLogin", new HashMap<>());
    }

    private boolean isUserLocked(UserModel user) {
        String lockoutTimestamp = user.getFirstAttribute(LOCKOUT_TIMESTAMP_KEY);
        if (lockoutTimestamp == null) {
            return false;
        }

        long lockoutTime = Long.parseLong(lockoutTimestamp);
        long currentTime = Time.currentTimeMillis();
        long lockoutDuration = getLockoutDuration(user);

        // If lockout period has expired, reset and unlock
        if (currentTime >= lockoutTime + lockoutDuration) {
            resetFailedAttempts(user);
            return false;
        }
        return true;
    }

    private long getLockoutDuration(UserModel user) {
        int failedAttempts = getFailedAttempts(user);
        if (failedAttempts >= 6) return 24 * 60 * 60 * 1000; // 24 hours
        if (failedAttempts == 5) return 20 * 60 * 1000; // 20 minutes
        if (failedAttempts == 4) return 10 * 60 * 1000; // 10 minutes
        if (failedAttempts == 3) return 5 * 60 * 1000; // 5 minutes
        return 0;
    }

    private long calculateRemainingLockoutTime(UserModel user) {
        String lockoutTimestamp = user.getFirstAttribute(LOCKOUT_TIMESTAMP_KEY);
        if (lockoutTimestamp == null) {
            return 0;
        }

        long lockoutTime = Long.parseLong(lockoutTimestamp);
        long currentTime = Time.currentTimeMillis();
        long lockoutDuration = getLockoutDuration(user);
        return Math.max(0, (lockoutTime + lockoutDuration) - currentTime);
    }

    private int getFailedAttempts(UserModel user) {
        String attempts = user.getFirstAttribute(FAILED_ATTEMPTS_KEY);
        return attempts == null ? 0 : Integer.parseInt(attempts);
    }

    private void handleFailedAttempt(AuthenticationFlowContext context, UserModel user) {
        int failedAttempts = getFailedAttempts(user) + 1;
        user.setSingleAttribute(FAILED_ATTEMPTS_KEY, String.valueOf(failedAttempts));

        if (failedAttempts >= 3) {
            user.setSingleAttribute(LOCKOUT_TIMESTAMP_KEY, String.valueOf(Time.currentTimeMillis()));
        }
    }

    private void resetFailedAttempts(UserModel user) {
        user.setSingleAttribute(FAILED_ATTEMPTS_KEY, "0");
        user.removeAttribute(LOCKOUT_TIMESTAMP_KEY);
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        // Always return true as we're using a fixed OTP code
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