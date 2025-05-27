package com.example.keycloak.util;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;
import org.jboss.logging.Logger;

import java.util.Map;

/**
 * Utility class to handle retry logic and account lockout functionality
 * Implements the progressive lockout strategy as per business requirements
 */
public class RetryLogicHandler {

    private static final Logger logger = Logger.getLogger(RetryLogicHandler.class);

    // Lockout durations in minutes based on attempt count
    private static final int[] LOCKOUT_DURATIONS = {
            0,    // 1st attempt - no lockout
            0,    // 2nd attempt - no lockout
            5,    // 3rd attempt - 5 minutes
            10,   // 4th attempt - 10 minutes
            20,   // 5th attempt - 20 minutes
            1440  // 6+ attempts - 24 hours (1440 minutes)
    };

    private static final String FAILED_ATTEMPTS_SUFFIX = "_failed_count";
    private static final String LAST_ATTEMPT_SUFFIX = "_last_attempt";
    private static final String LOCKED_UNTIL_SUFFIX = "_locked_until";
    private static final String RESET_TIME_SUFFIX = "_reset_time";

    // 24 hours in milliseconds for auto-reset
    private static final long AUTO_RESET_PERIOD = 24 * 60 * 60 * 1000L;

    /**
     * Records a failed attempt and determines if account should be locked
     * @param context Authentication flow context
     * @param identifier Unique identifier (e.g., legalId_phone)
     * @param type Type of attempt (login, otp)
     * @return LockoutResult containing lockout status and message
     */
    public static LockoutResult recordFailedAttempt(AuthenticationFlowContext context,
                                                    String identifier,
                                                    String type) {
        String key = getFailedAttemptsKey(identifier, type);

        // Check if we need to reset due to 24-hour period
        checkAndResetIfNeeded(context, key);

        // Get current failed attempts
        int currentAttempts = getCurrentFailedAttempts(context, key);
        currentAttempts++;

        // Store updated attempt count and timestamp
        context.getAuthenticationSession().setUserSessionNote(key + FAILED_ATTEMPTS_SUFFIX, String.valueOf(currentAttempts));
        context.getAuthenticationSession().setUserSessionNote(key + LAST_ATTEMPT_SUFFIX, String.valueOf(System.currentTimeMillis()));

        logger.warnf("Failed %s attempt #%d for identifier: %s", type, currentAttempts, identifier);

        // Determine lockout duration
        int lockoutMinutes = getLockoutDuration(currentAttempts);

        LockoutResult result = new LockoutResult();
        result.setAttemptCount(currentAttempts);
        result.setMaxAttempts(getMaxAttemptsBeforePermanentLock());

        if (lockoutMinutes > 0) {
            long lockoutUntil = System.currentTimeMillis() + (lockoutMinutes * 60 * 1000L);
            context.getAuthenticationSession().setAuthNote(key + LOCKED_UNTIL_SUFFIX, String.valueOf(lockoutUntil));

            result.setLocked(true);
            result.setLockoutDurationMinutes(lockoutMinutes);
            result.setLockoutUntil(lockoutUntil);
            result.setMessage(generateLockoutMessage(currentAttempts, lockoutMinutes));

            logger.warnf("Account locked for identifier: %s, duration: %d minutes", identifier, lockoutMinutes);
        } else {
            result.setLocked(false);
            int remainingAttempts = getRemainingAttempts(currentAttempts);
            result.setMessage(generateWarningMessage(currentAttempts, remainingAttempts));
        }

        return result;
    }

    /**
     * Checks if an account is currently locked
     * @param context Authentication flow context
     * @param identifier Unique identifier
     * @param type Type of attempt (login, otp)
     * @return LockoutStatus with current lock information
     */
    public static LockoutStatus checkLockoutStatus(AuthenticationFlowContext context,
                                                   String identifier,
                                                   String type) {
        String key = getFailedAttemptsKey(identifier, type);

        // Check if we need to reset due to 24-hour period
        checkAndResetIfNeeded(context, key);

        String lockedUntilStr = context.getAuthenticationSession().getAuthNote(key + LOCKED_UNTIL_SUFFIX);

        LockoutStatus status = new LockoutStatus();

        if (lockedUntilStr != null) {
            long lockedUntil = Long.parseLong(lockedUntilStr);
            long currentTime = System.currentTimeMillis();

            if (currentTime < lockedUntil) {
                // Still locked
                status.setLocked(true);
                status.setRemainingLockoutMs(lockedUntil - currentTime);
                status.setMessage(generateCurrentLockoutMessage(lockedUntil - currentTime));
            } else {
                // Lock expired, but don't reset failed attempts yet
                status.setLocked(false);
                status.setMessage("Thời gian khóa đã hết. Bạn có thể thử lại.");

                // Remove lockout timestamp but keep failed attempts count
                context.getAuthenticationSession().removeAuthNote(key + LOCKED_UNTIL_SUFFIX);
            }
        } else {
            status.setLocked(false);
        }

        status.setFailedAttempts(getCurrentFailedAttempts(context, key));
        return status;
    }

    /**
     * Resets failed attempts for successful authentication
     * @param context Authentication flow context
     * @param identifier Unique identifier
     * @param type Type of attempt (login, otp)
     */
    public static void resetFailedAttempts(AuthenticationFlowContext context,
                                           String identifier,
                                           String type) {
        String key = getFailedAttemptsKey(identifier, type);

        context.getAuthenticationSession().removeAuthNote(key + FAILED_ATTEMPTS_SUFFIX);
        context.getAuthenticationSession().removeAuthNote(key + LAST_ATTEMPT_SUFFIX);
        context.getAuthenticationSession().removeAuthNote(key + LOCKED_UNTIL_SUFFIX);
        context.getAuthenticationSession().removeAuthNote(key + RESET_TIME_SUFFIX);

        logger.infof("Reset failed attempts for identifier: %s, type: %s", identifier, type);
    }

    private static void checkAndResetIfNeeded(AuthenticationFlowContext context, String key) {
        String resetTimeStr = context.getAuthenticationSession().getAuthNote(key + RESET_TIME_SUFFIX);
        long currentTime = System.currentTimeMillis();

        if (resetTimeStr == null) {
            // First time, set reset time
            context.getAuthenticationSession().setAuthNote(key + RESET_TIME_SUFFIX, String.valueOf(currentTime + AUTO_RESET_PERIOD));
        } else {
            long resetTime = Long.parseLong(resetTimeStr);
            if (currentTime >= resetTime) {
                // 24 hours passed, reset everything
                logger.infof("Auto-resetting failed attempts after 24 hours for key: %s", key);
                context.getAuthenticationSession().removeAuthNote(key + FAILED_ATTEMPTS_SUFFIX);
                context.getAuthenticationSession().removeAuthNote(key + LAST_ATTEMPT_SUFFIX);
                context.getAuthenticationSession().removeAuthNote(key + LOCKED_UNTIL_SUFFIX);
                context.getAuthenticationSession().setAuthNote(key + RESET_TIME_SUFFIX, String.valueOf(currentTime + AUTO_RESET_PERIOD));
            }
        }
    }

    private static int getCurrentFailedAttempts(AuthenticationFlowContext context, String key) {
        String countStr = context.getAuthenticationSession().getAuthNote(key + FAILED_ATTEMPTS_SUFFIX);
        return countStr != null ? Integer.parseInt(countStr) : 0;
    }

    private static String getFailedAttemptsKey(String identifier, String type) {
        return type + "_failed_" + identifier;
    }

    private static int getLockoutDuration(int attemptCount) {
        if (attemptCount <= 2) {
            return 0; // No lockout for first 2 attempts
        } else if (attemptCount >= 6) {
            return LOCKOUT_DURATIONS[5]; // 24 hours for 6+ attempts
        } else {
            return LOCKOUT_DURATIONS[attemptCount - 1];
        }
    }

    private static int getRemainingAttempts(int currentAttempts) {
        return Math.max(0, 3 - currentAttempts); // 3 free attempts before first lockout
    }

    private static int getMaxAttemptsBeforePermanentLock() {
        return 6; // After 6 attempts, lockout is 24 hours
    }

    private static String generateLockoutMessage(int attemptCount, int lockoutMinutes) {
        String timeDesc;
        if (lockoutMinutes >= 1440) {
            timeDesc = "24 giờ";
        } else if (lockoutMinutes >= 60) {
            int hours = lockoutMinutes / 60;
            timeDesc = hours + " giờ";
        } else {
            timeDesc = lockoutMinutes + " phút";
        }

        return String.format(
                "Tài khoản của Quý khách bị khóa do nhập sai thông tin nhiều lần. " +
                        "Tài khoản sẽ tự động mở lại sau %s. " +
                        "Quý khách có thể truy cập tại đây [Link mở khóa] để yêu cầu mở khóa. " +
                        "Vui lòng liên hệ VPBank SME gần nhất nếu cần hỗ trợ.\n" +
                        "Danh sách Trung tâm VPBank SME: Xem tại đây\n" +
                        "Tổng đài hỗ trợ: 1900 234 568 #2",
                timeDesc
        );
    }

    private static String generateWarningMessage(int attemptCount, int remainingAttempts) {
        if (remainingAttempts <= 0) {
            return "Thông tin đăng nhập không chính xác.";
        }

        if (remainingAttempts == 1) {
            return "Thông tin đăng nhập không chính xác. Bạn còn 1 lần thử nữa trước khi tài khoản bị khóa.";
        }

        return String.format("Thông tin đăng nhập không chính xác. Bạn còn %d lần thử nữa.", remainingAttempts);
    }

    private static String generateCurrentLockoutMessage(long remainingMs) {
        long remainingMinutes = remainingMs / (60 * 1000);
        long remainingHours = remainingMinutes / 60;

        String timeDesc;
        if (remainingHours > 0) {
            timeDesc = remainingHours + " giờ " + (remainingMinutes % 60) + " phút";
        } else {
            timeDesc = remainingMinutes + " phút";
        }

        return String.format(
                "Tài khoản của Quý khách đang bị khóa. Vui lòng thử lại sau %s.\n" +
                        "Danh sách Trung tâm VPBank SME: Xem tại đây\n" +
                        "Tổng đài hỗ trợ: 1900 234 568 #2",
                timeDesc
        );
    }

    // Helper classes
    public static class LockoutResult {
        private boolean locked;
        private int attemptCount;
        private int maxAttempts;
        private int lockoutDurationMinutes;
        private long lockoutUntil;
        private String message;

        // Getters and setters
        public boolean isLocked() { return locked; }
        public void setLocked(boolean locked) { this.locked = locked; }

        public int getAttemptCount() { return attemptCount; }
        public void setAttemptCount(int attemptCount) { this.attemptCount = attemptCount; }

        public int getMaxAttempts() { return maxAttempts; }
        public void setMaxAttempts(int maxAttempts) { this.maxAttempts = maxAttempts; }

        public int getLockoutDurationMinutes() { return lockoutDurationMinutes; }
        public void setLockoutDurationMinutes(int lockoutDurationMinutes) { this.lockoutDurationMinutes = lockoutDurationMinutes; }

        public long getLockoutUntil() { return lockoutUntil; }
        public void setLockoutUntil(long lockoutUntil) { this.lockoutUntil = lockoutUntil; }

        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }
    }

    public static class LockoutStatus {
        private boolean locked;
        private int failedAttempts;
        private long remainingLockoutMs;
        private String message;

        // Getters and setters
        public boolean isLocked() { return locked; }
        public void setLocked(boolean locked) { this.locked = locked; }

        public int getFailedAttempts() { return failedAttempts; }
        public void setFailedAttempts(int failedAttempts) { this.failedAttempts = failedAttempts; }

        public long getRemainingLockoutMs() { return remainingLockoutMs; }
        public void setRemainingLockoutMs(long remainingLockoutMs) { this.remainingLockoutMs = remainingLockoutMs; }

        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }
    }
}