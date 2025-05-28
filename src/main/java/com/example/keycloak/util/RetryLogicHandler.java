package com.example.keycloak.util;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.UserModel;
import org.jboss.logging.Logger;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Enhanced Retry Logic Handler with User Attributes and In-Memory Cache
 * Uses custom user attributes: lockedAt, lockDuration
 * Implements in-memory cache for performance optimization
 */
public class RetryLogicHandler {

    private static final Logger logger = Logger.getLogger(RetryLogicHandler.class);

    // Custom user attributes
    private static final String LOCKED_AT_ATTR = "lockedAt";
    private static final String LOCK_DURATION_ATTR = "lockDuration";
    private static final String FAILED_ATTEMPTS_ATTR = "failedAttempts";
    private static final String LAST_ATTEMPT_AT_ATTR = "lastAttemptAt";

    // Lockout durations in minutes based on attempt count
    private static final int[] LOCKOUT_DURATIONS = {
            0,    // 1st attempt - no lockout
            0,    // 2nd attempt - no lockout
            5,    // 3rd attempt - 5 minutes
            10,   // 4th attempt - 10 minutes
            20,   // 5th attempt - 20 minutes
            1440  // 6+ attempts - 24 hours (1440 minutes)
    };

    // 24 hours in milliseconds for auto-reset
    private static final long AUTO_RESET_PERIOD = 24 * 60 * 60 * 1000L;

    // In-memory cache for lockout status
    private static final ConcurrentHashMap<String, CachedLockoutInfo> lockoutCache = new ConcurrentHashMap<>();
    private static final ScheduledExecutorService cacheCleanupExecutor = Executors.newSingleThreadScheduledExecutor();

    static {
        // Clean up expired cache entries every 5 minutes
        cacheCleanupExecutor.scheduleAtFixedRate(() -> {
            long currentTime = System.currentTimeMillis();
            lockoutCache.entrySet().removeIf(entry -> {
                CachedLockoutInfo info = entry.getValue();
                return currentTime > info.unlockTime || currentTime > info.cacheExpiry;
            });
        }, 5, 5, TimeUnit.MINUTES);
    }

    /**
     * Records a failed attempt and determines if account should be locked
     */
    public static LockoutResult recordFailedAttempt(AuthenticationFlowContext context,
                                                    String identifier,
                                                    String type) {
        UserModel user = context.getUser();
        if (user == null) {
            logger.warn("No user found in context for failed attempt recording");
            return createUnlockedResult(1);
        }

        // Check if we need auto-reset (24 hours)
        checkAndResetIfNeeded(user, type);

        // Get current failed attempts
        int currentAttempts = getCurrentFailedAttempts(user, type);
        currentAttempts++;

        // Update user attributes
        user.setAttribute(FAILED_ATTEMPTS_ATTR + "_" + type, List.of(String.valueOf(currentAttempts)));
        user.setAttribute(LAST_ATTEMPT_AT_ATTR + "_" + type, List.of(String.valueOf(System.currentTimeMillis())));

        logger.warnf("Failed %s attempt #%d for user: %s", type, currentAttempts, user.getUsername());

        // Determine lockout duration
        int lockoutMinutes = getLockoutDuration(currentAttempts);

        LockoutResult result = new LockoutResult();
        result.setAttemptCount(currentAttempts);

        if (lockoutMinutes > 0) {
            long lockedAt = System.currentTimeMillis();
            int lockDurationSeconds = lockoutMinutes * 60;

            // Store in user attributes
            user.setAttribute(LOCKED_AT_ATTR + "_" + type, List.of(String.valueOf(lockedAt)));
            user.setAttribute(LOCK_DURATION_ATTR + "_" + type, List.of(String.valueOf(lockDurationSeconds)));

            // Update cache
            String cacheKey = getCacheKey(user.getUsername(), type);
            long unlockTime = lockedAt + (lockDurationSeconds * 1000L);
            lockoutCache.put(cacheKey, new CachedLockoutInfo(
                    lockedAt,
                    lockDurationSeconds,
                    unlockTime,
                    System.currentTimeMillis() + (30 * 60 * 1000L) // Cache for 30 minutes
            ));

            result.setLocked(true);
            result.setLockDurationSeconds(lockDurationSeconds);
            result.setLockedAt(lockedAt);

            logger.warnf("Account locked for user: %s, type: %s, duration: %d minutes",
                    user.getUsername(), type, lockoutMinutes);
        } else {
            result.setLocked(false);
            // Remove from cache if exists
            lockoutCache.remove(getCacheKey(user.getUsername(), type));
        }

        return result;
    }

    /**
     * Checks if an account is currently locked
     * Uses cache first, then checks user attributes
     */
    public static LockoutStatus checkLockoutStatus(AuthenticationFlowContext context,
                                                   String identifier,
                                                   String type) {
        UserModel user = context.getUser();
        if (user == null) {
            // For login step, user might not be set yet, try to find by identifier
            if ("login".equals(type) && identifier != null) {
                user = context.getSession().users().getUserByUsername(context.getRealm(), identifier);
            }

            if (user == null) {
                return createUnlockedStatus();
            }
        }

        String cacheKey = getCacheKey(user.getUsername(), type);

        // Check cache first
        CachedLockoutInfo cachedInfo = lockoutCache.get(cacheKey);
        long currentTime = System.currentTimeMillis();

        if (cachedInfo != null && currentTime < cachedInfo.cacheExpiry) {
            if (currentTime < cachedInfo.unlockTime) {
                // Still locked according to cache
                return createLockedStatus(cachedInfo, currentTime);
            } else {
                // Cache says unlocked, but verify with user attributes
                lockoutCache.remove(cacheKey);
            }
        }

        // Check user attributes
        List<String> lockedAtList = user.getAttributes().get(LOCKED_AT_ATTR + "_" + type);
        if (lockedAtList == null || lockedAtList.isEmpty()) {
            // No lockedAt attribute = unlocked
            return createUnlockedStatus();
        }

        List<String> lockDurationList = user.getAttributes().get(LOCK_DURATION_ATTR + "_" + type);
        if (lockDurationList == null || lockDurationList.isEmpty()) {
            // No lockDuration attribute = unlocked
            user.removeAttribute(LOCKED_AT_ATTR + "_" + type);
            return createUnlockedStatus();
        }

        try {
            long lockedAt = Long.parseLong(lockedAtList.get(0));
            int lockDurationSeconds = Integer.parseInt(lockDurationList.get(0));
            long unlockTime = lockedAt + (lockDurationSeconds * 1000L);

            if (currentTime < unlockTime) {
                // Still locked
                // Update cache
                lockoutCache.put(cacheKey, new CachedLockoutInfo(
                        lockedAt,
                        lockDurationSeconds,
                        unlockTime,
                        System.currentTimeMillis() + (30 * 60 * 1000L)
                ));

                LockoutStatus status = new LockoutStatus();
                status.setLocked(true);
                status.setRemainingLockoutMs(unlockTime - currentTime);
                status.setLockDurationSeconds(lockDurationSeconds);
                status.setLockedAt(lockedAt);
                status.setFailedAttempts(getCurrentFailedAttempts(user, type));
                return status;
            } else {
                // Lock expired - remove attributes but keep failed attempts
                user.removeAttribute(LOCKED_AT_ATTR + "_" + type);
                user.removeAttribute(LOCK_DURATION_ATTR + "_" + type);
                lockoutCache.remove(cacheKey);

                LockoutStatus status = createUnlockedStatus();
                status.setFailedAttempts(getCurrentFailedAttempts(user, type));
                return status;
            }
        } catch (NumberFormatException e) {
            logger.errorf("Invalid lockout data for user %s, type %s. Clearing attributes.",
                    user.getUsername(), type);
            user.removeAttribute(LOCKED_AT_ATTR + "_" + type);
            user.removeAttribute(LOCK_DURATION_ATTR + "_" + type);
            return createUnlockedStatus();
        }
    }

    /**
     * Resets failed attempts for successful authentication
     */
    public static void resetFailedAttempts(AuthenticationFlowContext context,
                                           String identifier,
                                           String type) {
        UserModel user = context.getUser();
        if (user == null) {
            logger.warn("No user found in context for reset");
            return;
        }

        // Remove all lockout and attempt attributes for this type
        user.removeAttribute(FAILED_ATTEMPTS_ATTR + "_" + type);
        user.removeAttribute(LAST_ATTEMPT_AT_ATTR + "_" + type);
        user.removeAttribute(LOCKED_AT_ATTR + "_" + type);
        user.removeAttribute(LOCK_DURATION_ATTR + "_" + type);

        // Remove from cache
        lockoutCache.remove(getCacheKey(user.getUsername(), type));

        logger.infof("Reset failed attempts for user: %s, type: %s", user.getUsername(), type);
    }

    // Private helper methods
    private static void checkAndResetIfNeeded(UserModel user, String type) {
        List<String> lastAttemptList = user.getAttributes().get(LAST_ATTEMPT_AT_ATTR + "_" + type);
        if (lastAttemptList == null || lastAttemptList.isEmpty()) {
            return;
        }

        try {
            long lastAttempt = Long.parseLong(lastAttemptList.get(0));
            long currentTime = System.currentTimeMillis();

            if (currentTime - lastAttempt >= AUTO_RESET_PERIOD) {
                // Auto-reset after 24 hours
                logger.infof("Auto-resetting failed attempts after 24 hours for user: %s, type: %s",
                        user.getUsername(), type);

                user.removeAttribute(FAILED_ATTEMPTS_ATTR + "_" + type);
                user.removeAttribute(LAST_ATTEMPT_AT_ATTR + "_" + type);
                user.removeAttribute(LOCKED_AT_ATTR + "_" + type);
                user.removeAttribute(LOCK_DURATION_ATTR + "_" + type);
                lockoutCache.remove(getCacheKey(user.getUsername(), type));
            }
        } catch (NumberFormatException e) {
            logger.errorf("Invalid lastAttemptAt data for user %s, type %s", user.getUsername(), type);
        }
    }

    private static int getCurrentFailedAttempts(UserModel user, String type) {
        List<String> attemptsList = user.getAttributes().get(FAILED_ATTEMPTS_ATTR + "_" + type);
        if (attemptsList == null || attemptsList.isEmpty()) {
            return 0;
        }
        try {
            return Integer.parseInt(attemptsList.get(0));
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static String getCacheKey(String username, String type) {
        return type + "_" + username;
    }

    private static int getLockoutDuration(int attemptCount) {
        if (attemptCount <= 2) {
            return 0;
        } else if (attemptCount >= 6) {
            return LOCKOUT_DURATIONS[5];
        } else {
            return LOCKOUT_DURATIONS[attemptCount - 1];
        }
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

    private static LockoutStatus createLockedStatus(CachedLockoutInfo cachedInfo, long currentTime) {
        LockoutStatus status = new LockoutStatus();
        status.setLocked(true);
        status.setRemainingLockoutMs(cachedInfo.unlockTime - currentTime);
        status.setLockDurationSeconds(cachedInfo.lockDurationSeconds);
        status.setLockedAt(cachedInfo.lockedAt);
        return status;
    }

    // Helper classes
    public static class LockoutResult {
        private boolean locked;
        private int attemptCount;
        private int lockDurationSeconds;
        private long lockedAt;

        // Getters and setters
        public boolean isLocked() { return locked; }
        public void setLocked(boolean locked) { this.locked = locked; }

        public int getAttemptCount() { return attemptCount; }
        public void setAttemptCount(int attemptCount) { this.attemptCount = attemptCount; }

        public int getLockDurationSeconds() { return lockDurationSeconds; }
        public void setLockDurationSeconds(int lockDurationSeconds) { this.lockDurationSeconds = lockDurationSeconds; }

        public long getLockedAt() { return lockedAt; }
        public void setLockedAt(long lockedAt) { this.lockedAt = lockedAt; }
    }

    public static class LockoutStatus {
        private boolean locked;
        private int failedAttempts;
        private long remainingLockoutMs;
        private int lockDurationSeconds;
        private long lockedAt;

        // Getters and setters
        public boolean isLocked() { return locked; }
        public void setLocked(boolean locked) { this.locked = locked; }

        public int getFailedAttempts() { return failedAttempts; }
        public void setFailedAttempts(int failedAttempts) { this.failedAttempts = failedAttempts; }

        public long getRemainingLockoutMs() { return remainingLockoutMs; }
        public void setRemainingLockoutMs(long remainingLockoutMs) { this.remainingLockoutMs = remainingLockoutMs; }

        public int getLockDurationSeconds() { return lockDurationSeconds; }
        public void setLockDurationSeconds(int lockDurationSeconds) { this.lockDurationSeconds = lockDurationSeconds; }

        public long getLockedAt() { return lockedAt; }
        public void setLockedAt(long lockedAt) { this.lockedAt = lockedAt; }
    }

    // Cache data structure
    private static class CachedLockoutInfo {
        final long lockedAt;
        final int lockDurationSeconds;
        final long unlockTime;
        final long cacheExpiry;

        CachedLockoutInfo(long lockedAt, int lockDurationSeconds, long unlockTime, long cacheExpiry) {
            this.lockedAt = lockedAt;
            this.lockDurationSeconds = lockDurationSeconds;
            this.unlockTime = unlockTime;
            this.cacheExpiry = cacheExpiry;
        }
    }

    // Cleanup method for graceful shutdown
    public static void shutdown() {
        cacheCleanupExecutor.shutdown();
        try {
            if (!cacheCleanupExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                cacheCleanupExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            cacheCleanupExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}