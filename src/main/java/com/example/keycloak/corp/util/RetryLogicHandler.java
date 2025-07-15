package com.example.keycloak.corp.util;

import org.infinispan.Cache;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.connections.infinispan.InfinispanConnectionProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.UserModel;
import org.jboss.logging.Logger;

import java.io.Serializable;
import java.util.List;

public class RetryLogicHandler {

    private static final Logger logger = Logger.getLogger(RetryLogicHandler.class);

    private static final String CACHE_NAME = "otpBizconnectFailCount";

    private static final String USER_ATTR_LOCKED_AT = "lockedAt";
    private static final String USER_ATTR_LOCK_DURATION = "lockDuration";

    private static final int[] DEFAULT_LOCKOUT_DURATIONS = {
            0,    // 1st no lockout
            0,    // 2nd no lockout
            5,    // 3rd 5 minutes
            10,   // 4th 10 minutes
            20,   // 5th 20 minutes
            1440  // 6+  24 hours (1440 minutes)
    };

    private static final long DEFAULT_AUTO_RESET_PERIOD = 24 * 60 * 60 * 1000L; // 24 hours

    public static LockoutResult recordFailedAttempt(AuthenticationFlowContext context,
                                                    String identifier,
                                                    String type) {
        UserModel user = context.getUser();
        if (user == null) {
            logger.warn("No user found in context for failed attempt recording");
            return createUnlockedResult(1);
        }

        try {
            Cache<String, FailCountData> cache = getCache(context);
            String cacheKey = getCacheKey(user.getUsername(), type);

            FailCountData failData = cache.get(cacheKey);
            if (failData == null) {
                failData = new FailCountData();
            }

            checkAndResetIfNeeded(failData, cache, cacheKey, context);

            failData.incrementAttempts();
            failData.setLastAttemptAt(System.currentTimeMillis());

            int lockoutMinutes = getLockoutDuration(failData.getAttemptCount(), context);

            LockoutResult result = new LockoutResult();
            result.setAttemptCount(failData.getAttemptCount());

            if (lockoutMinutes > 0) {
                long lockedAt = System.currentTimeMillis();
                int lockDuration = lockoutMinutes * 60;

                failData.setLockedAt(lockedAt);
                failData.setLockDuration(lockDuration);

                if ("otp".equals(type)) {
                    saveUserLockoutInfo(user, lockedAt, lockDuration);
                }

                result.setLocked(true);
                result.setLockDuration(lockDuration);
                result.setLockedAt(lockedAt);

                logger.warnf("Account locked for user: %s, type: %s, duration: %d minutes",
                        user.getUsername(), type, lockoutMinutes);
            } else {
                result.setLocked(false);
            }

            cache.put(cacheKey, failData);

            logger.warnf("Failed %s attempt #%d for user: %s", type, failData.getAttemptCount(), user.getUsername());

            return result;

        } catch (Exception e) {
            logger.warnf("Cache error during recordFailedAttempt, bypassing lockout logic: %s", e.getMessage());
            return createUnlockedResult(1);
        }
    }

    public static LockoutStatus checkLockoutStatus(AuthenticationFlowContext context,
                                                   String identifier,
                                                   String type) {
        UserModel user = context.getUser();
        if (user == null) {
            if ("login".equals(type) && identifier != null) {
                user = context.getSession().users().getUserByUsername(context.getRealm(), identifier);
            }
            if (user == null) {
                return createUnlockedStatus();
            }
        }

        if ("otp".equals(type)) {
            LockoutStatus userAttrStatus = checkUserAttributeLockout(user);
            if (userAttrStatus.isLocked()) {
                return userAttrStatus;
            }
        }

        try {
            Cache<String, FailCountData> cache = getCache(context);
            String cacheKey = getCacheKey(user.getUsername(), type);

            FailCountData failData = cache.get(cacheKey);
            if (failData == null) {
                return createUnlockedStatus();
            }

            long currentTime = System.currentTimeMillis();

            if (failData.getLockedAt() > 0 && failData.getLockDuration() > 0) {
                long unlockTime = failData.getLockedAt() + (failData.getLockDuration() * 1000L);

                if (currentTime < unlockTime) {
                    LockoutStatus status = new LockoutStatus();
                    status.setLocked(true);
                    status.setRemainingLockoutMs(unlockTime - currentTime);
                    status.setLockDuration(failData.getLockDuration());
                    status.setLockedAt(failData.getLockedAt());
                    status.setFailedAttempts(failData.getAttemptCount());
                    return status;
                } else {
                    failData.clearLockData();
                    cache.put(cacheKey, failData);
                    if ("otp".equals(type)) {
                        clearUserLockoutInfo(user);
                    }
                }
            }

            LockoutStatus status = createUnlockedStatus();
            status.setFailedAttempts(failData.getAttemptCount());
            return status;

        } catch (Exception e) {
            logger.warnf("Cache error during checkLockoutStatus, checking user attributes for OTP: %s", e.getMessage());
            if ("otp".equals(type)) {
                return checkUserAttributeLockout(user);
            } else {
                return createUnlockedStatus();
            }
        }
    }

    public static void resetFailedAttempts(AuthenticationFlowContext context,
                                           String identifier,
                                           String type) {
        UserModel user = context.getUser();
        if (user == null) {
            logger.warn("No user found in context for reset");
            return;
        }
        try {
            Cache<String, FailCountData> cache = getCache(context);
            String cacheKey = getCacheKey(user.getUsername(), type);
            cache.remove(cacheKey);

            logger.infof("Reset failed attempts for user: %s, type: %s", user.getUsername(), type);
        } catch (Exception e) {
            logger.warnf("Cache error during reset (non-critical): %s", e.getMessage());
        }

        if ("otp".equals(type)) {
            clearUserLockoutInfo(user);
        }
    }

    private static void saveUserLockoutInfo(UserModel user, long lockedAt, int lockDuration) {
        try {
            user.setAttribute(USER_ATTR_LOCKED_AT, List.of(String.valueOf(lockedAt)));
            user.setAttribute(USER_ATTR_LOCK_DURATION, List.of(String.valueOf(lockDuration)));

            logger.infof("Saved OTP lockout info to user attributes: user=%s, lockedAt=%d, duration=%d",
                    user.getUsername(), lockedAt, lockDuration);
        } catch (Exception e) {
            logger.errorf("Failed to save OTP lockout info to user attributes: %s", e.getMessage());
        }
    }

    private static LockoutStatus checkUserAttributeLockout(UserModel user) {
        try {
            List<String> lockedAtList = user.getAttributes().get(USER_ATTR_LOCKED_AT);
            List<String> lockDurationList = user.getAttributes().get(USER_ATTR_LOCK_DURATION);

            if (lockedAtList == null || lockDurationList == null ||
                    lockedAtList.isEmpty() || lockDurationList.isEmpty()) {
                return createUnlockedStatus();
            }

            long lockedAt = Long.parseLong(lockedAtList.get(0));
            int lockDuration = Integer.parseInt(lockDurationList.get(0));

            long currentTime = System.currentTimeMillis();
            long unlockTime = lockedAt + (lockDuration * 1000L);

            if (currentTime < unlockTime) {
                LockoutStatus status = new LockoutStatus();
                status.setLocked(true);
                status.setRemainingLockoutMs(unlockTime - currentTime);
                status.setLockDuration(lockDuration);
                status.setLockedAt(lockedAt);
                return status;
            } else {
                clearUserLockoutInfo(user);
                return createUnlockedStatus();
            }

        } catch (Exception e) {
            logger.warnf("Error checking user attribute lockout: %s", e.getMessage());
            return createUnlockedStatus();
        }
    }

    private static void clearUserLockoutInfo(UserModel user) {
        try {
            user.removeAttribute(USER_ATTR_LOCKED_AT);
            user.removeAttribute(USER_ATTR_LOCK_DURATION);

            logger.infof("Cleared OTP lockout info from user attributes: user=%s", user.getUsername());
        } catch (Exception e) {
            logger.errorf("Failed to clear OTP lockout info from user attributes: %s", e.getMessage());
        }
    }

    // Cache management methods
    private static Cache<String, FailCountData> getCache(AuthenticationFlowContext context) {
        InfinispanConnectionProvider provider = context.getSession()
                .getProvider(InfinispanConnectionProvider.class);
        return provider.getCache(CACHE_NAME);
    }

    private static void checkAndResetIfNeeded(FailCountData failData,
                                              Cache<String, FailCountData> cache,
                                              String cacheKey,
                                              AuthenticationFlowContext context) {
        if (failData.getLastAttemptAt() > 0) {
            long currentTime = System.currentTimeMillis();
            long autoResetPeriod = getAutoResetPeriod(context);

            if (currentTime - failData.getLastAttemptAt() >= autoResetPeriod) {
                logger.infof("Auto-resetting failed attempts after configured period for cache key: %s", cacheKey);
                cache.remove(cacheKey);
                failData.reset();
            }
        }
    }

    private static String getCacheKey(String username, String type) {
        return type + "_" + username;
    }

    private static int getLockoutDuration(int attemptCount, AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();

        try {
            switch (attemptCount) {
                case 1:
                case 2:
                    return 0;
                case 3:
                    return Integer.parseInt(getConfigValue(config, "lockoutDuration3", "5"));
                case 4:
                    return Integer.parseInt(getConfigValue(config, "lockoutDuration4", "10"));
                case 5:
                    return Integer.parseInt(getConfigValue(config, "lockoutDuration5", "20"));
                default:
                    return Integer.parseInt(getConfigValue(config, "lockoutDuration6Plus", "1440"));
            }
        } catch (NumberFormatException e) {
            logger.warnf("Invalid lockout duration config, using defaults: %s", e.getMessage());
            // Fallback to default values
            if (attemptCount <= 2) {
                return 0;
            } else if (attemptCount >= 6) {
                return DEFAULT_LOCKOUT_DURATIONS[5];
            } else {
                return DEFAULT_LOCKOUT_DURATIONS[attemptCount - 1];
            }
        }
    }

    private static long getAutoResetPeriod(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        try {
            String minutes = getConfigValue(config, "autoResetPeriodMinutes", "1440");
            return Long.parseLong(minutes) * 60 * 1000L; // Convert to milliseconds
        } catch (NumberFormatException e) {
            logger.warnf("Invalid auto reset period config, using default: %s", e.getMessage());
            return DEFAULT_AUTO_RESET_PERIOD;
        }
    }

    private static String getConfigValue(AuthenticatorConfigModel config, String key, String defaultValue) {
        if (config == null || config.getConfig() == null) {
            return defaultValue;
        }
        return config.getConfig().getOrDefault(key, defaultValue);
    }

    private static LockoutResult createUnlockedResult(int attemptCount) {
        LockoutResult result = new LockoutResult();
        result.setLocked(false);
        result.setAttemptCount(attemptCount);
        return result;
    }

    private static LockoutStatus createUnlockedStatus() {
        LockoutStatus status = new LockoutStatus();
        status.setLocked(false);
        return status;
    }

    public static class FailCountData implements Serializable {
        private static final long serialVersionUID = 1L;

        private int attemptCount = 0;
        private long lastAttemptAt = 0;
        private long lockedAt = 0;
        private int lockDuration = 0;

        public int getAttemptCount() {
            return attemptCount;
        }

        public void setAttemptCount(int attemptCount) {
            this.attemptCount = attemptCount;
        }

        public void incrementAttempts() {
            this.attemptCount++;
        }

        public long getLastAttemptAt() {
            return lastAttemptAt;
        }

        public void setLastAttemptAt(long lastAttemptAt) {
            this.lastAttemptAt = lastAttemptAt;
        }

        public long getLockedAt() {
            return lockedAt;
        }

        public void setLockedAt(long lockedAt) {
            this.lockedAt = lockedAt;
        }

        public int getLockDuration() {
            return lockDuration;
        }

        public void setLockDuration(int lockDuration) {
            this.lockDuration = lockDuration;
        }

        public void clearLockData() {
            this.lockedAt = 0;
            this.lockDuration = 0;
        }

        public void reset() {
            this.attemptCount = 0;
            this.lastAttemptAt = 0;
            this.lockedAt = 0;
            this.lockDuration = 0;
        }

        @Override
        public String toString() {
            return "FailCountData{" +
                    "attemptCount=" + attemptCount +
                    ", lastAttemptAt=" + lastAttemptAt +
                    ", lockedAt=" + lockedAt +
                    ", lockDuration=" + lockDuration +
                    '}';
        }
    }

    // Keep existing inner classes - UNCHANGED
    public static class LockoutResult {
        private boolean locked;
        private int attemptCount;
        private int lockDuration;
        private long lockedAt;

        public boolean isLocked() {
            return locked;
        }

        public void setLocked(boolean locked) {
            this.locked = locked;
        }

        public int getAttemptCount() {
            return attemptCount;
        }

        public void setAttemptCount(int attemptCount) {
            this.attemptCount = attemptCount;
        }

        public int getLockDuration() {
            return lockDuration;
        }

        public void setLockDuration(int lockDuration) {
            this.lockDuration = lockDuration;
        }

        public long getLockedAt() {
            return lockedAt;
        }

        public void setLockedAt(long lockedAt) {
            this.lockedAt = lockedAt;
        }
    }

    public static class LockoutStatus {
        private boolean locked;
        private int failedAttempts;
        private long remainingLockoutMs;
        private int lockDuration;
        private long lockedAt;

        public boolean isLocked() {
            return locked;
        }

        public void setLocked(boolean locked) {
            this.locked = locked;
        }

        public int getFailedAttempts() {
            return failedAttempts;
        }

        public void setFailedAttempts(int failedAttempts) {
            this.failedAttempts = failedAttempts;
        }

        public long getRemainingLockoutMs() {
            return remainingLockoutMs;
        }

        public void setRemainingLockoutMs(long remainingLockoutMs) {
            this.remainingLockoutMs = remainingLockoutMs;
        }

        public int getLockDuration() {
            return lockDuration;
        }

        public void setLockDuration(int lockDuration) {
            this.lockDuration = lockDuration;
        }

        public long getLockedAt() {
            return lockedAt;
        }

        public void setLockedAt(long lockedAt) {
            this.lockedAt = lockedAt;
        }
    }
}