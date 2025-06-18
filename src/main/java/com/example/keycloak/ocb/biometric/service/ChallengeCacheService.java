package com.example.keycloak.ocb.biometric.service;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.services.ServicesLogger;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class ChallengeCacheService {

    private static final ConcurrentHashMap<String, ChallengeData> challengeCache = new ConcurrentHashMap<>();
    private static final ScheduledExecutorService cleanupExecutor = Executors.newSingleThreadScheduledExecutor();

    static {
        cleanupExecutor.scheduleAtFixedRate(() -> {
            long now = System.currentTimeMillis();
            challengeCache.entrySet().removeIf(entry ->
                    now - entry.getValue().timestamp > 300000); // 5 minutes
        }, 1, 1, TimeUnit.MINUTES);
    }

    public static class ChallengeData {
        public final String challenge;
        public final String username;
        public final String userId;
        public final long timestamp;

        public ChallengeData(String challenge, String username, String userId) {
            this.challenge = challenge;
            this.username = username;
            this.userId = userId;
            this.timestamp = System.currentTimeMillis();
        }

        public boolean isExpired() {
            return (System.currentTimeMillis() - timestamp) > 300000; // 5 minutes
        }
    }

    // ========================= REGISTRATION METHODS =========================

    /**
     * Store registration challenge for user
     */
    public static void storeRegistrationChallenge(String challenge, String username, String userId) {
        String challengeKey = "register:" + userId;
        ChallengeData data = new ChallengeData(challenge, username, userId);
        challengeCache.put(challengeKey, data);
        ServicesLogger.LOGGER.info("Stored registration challenge in cache for user: " + username);
    }

    /**
     * Retrieve registration challenge by user ID
     */
    public static ChallengeData getRegistrationChallenge(String userId) {
        String challengeKey = "register:" + userId;
        ChallengeData data = challengeCache.get(challengeKey);

        if (data != null) {
            if (data.isExpired()) {
                challengeCache.remove(challengeKey);
                ServicesLogger.LOGGER.warn("Registration challenge expired for user: " + data.username);
                return null;
            }

            ServicesLogger.LOGGER.info("Retrieved registration challenge for user: " + data.username);
            return data;
        }

        ServicesLogger.LOGGER.warn("No registration challenge found for userId: " + userId);
        return null;
    }

    /**
     * Retrieve registration challenge by username (fallback)
     */
    public static ChallengeData getRegistrationChallengeByUsername(String username) {
        // Search cache for username match with register prefix
        for (String key : challengeCache.keySet()) {
            if (key.startsWith("register:")) {
                ChallengeData data = challengeCache.get(key);
                if (data != null && username.equals(data.username) && !data.isExpired()) {
                    ServicesLogger.LOGGER.info("Found registration challenge by username: " + username);
                    return data;
                }
            }
        }

        ServicesLogger.LOGGER.warn("No registration challenge found for username: " + username);
        return null;
    }

    /**
     * Clear registration challenge for user
     */
    public static void clearRegistrationChallenge(String userId) {
        String challengeKey = "register:" + userId;
        ChallengeData removed = challengeCache.remove(challengeKey);

        if (removed != null) {
            ServicesLogger.LOGGER.info("Cleared registration challenge for user: " + removed.username);
        }
    }

    // ========================= AUTHENTICATION METHODS =========================

    /**
     * Store authentication challenge for user
     */
    public static void storeChallengeForUser(String challenge, String username, String userId) {
        String challengeKey = "auth:" + userId;
        ChallengeData data = new ChallengeData(challenge, username, userId);
        challengeCache.put(challengeKey, data);
        ServicesLogger.LOGGER.info("Stored auth challenge in cache for user: " + username);
    }

    /**
     * Retrieve authentication challenge by user ID
     */
    public static ChallengeData getAuthChallenge(String userId) {
        String challengeKey = "auth:" + userId;
        ChallengeData data = challengeCache.get(challengeKey);

        if (data != null) {
            if (data.isExpired()) {
                challengeCache.remove(challengeKey);
                ServicesLogger.LOGGER.warn("Auth challenge expired for user: " + data.username);
                return null;
            }

            ServicesLogger.LOGGER.info("Retrieved auth challenge for user: " + data.username);
            return data;
        }

        ServicesLogger.LOGGER.warn("No auth challenge found for userId: " + userId);
        return null;
    }

    /**
     * Retrieve authentication challenge by username (fallback)
     */
    public static ChallengeData getAuthChallengeByUsername(String username) {
        // Search cache for username match with auth prefix
        for (String key : challengeCache.keySet()) {
            if (key.startsWith("auth:")) {
                ChallengeData data = challengeCache.get(key);
                if (data != null && username.equals(data.username) && !data.isExpired()) {
                    ServicesLogger.LOGGER.info("Found auth challenge by username: " + username);
                    return data;
                }
            }
        }

        ServicesLogger.LOGGER.warn("No auth challenge found for username: " + username);
        return null;
    }

    /**
     * Clear authentication challenge for user
     */
    public static void clearAuthChallenge(String userId) {
        String challengeKey = "auth:" + userId;
        ChallengeData removed = challengeCache.remove(challengeKey);

        if (removed != null) {
            ServicesLogger.LOGGER.info("Cleared auth challenge for user: " + removed.username);
        }
    }

    // ========================= GENERIC/LEGACY METHODS =========================

    /**
     * Store challenge with auto-generated key (legacy method)
     */
    public static String storeChallenge(String challenge, UserModel user) {
        String challengeKey = generateChallengeKey(user.getId(), challenge);
        ChallengeData data = new ChallengeData(challenge, user.getUsername(), user.getId());

        challengeCache.put(challengeKey, data);

        ServicesLogger.LOGGER.info("Stored challenge in cache with key: " + challengeKey +
                " for user: " + user.getUsername());

        return challengeKey;
    }

    /**
     * Retrieve and remove challenge (legacy method)
     */
    public static ChallengeData getAndRemoveChallenge(String challengeKey) {
        ChallengeData data = challengeCache.remove(challengeKey);

        if (data != null && !data.isExpired()) {
            ServicesLogger.LOGGER.info("Retrieved and removed challenge: " + challengeKey);
            return data;
        }

        return null;
    }

    /**
     * Generate unique challenge key (legacy method)
     */
    private static String generateChallengeKey(String userId, String challenge) {
        return "challenge:" + userId + ":" + challenge.hashCode();
    }

    // ========================= UTILITY METHODS =========================

    /**
     * Get cache statistics for debugging
     */
    public static String getCacheStats() {
        long now = System.currentTimeMillis();
        int total = challengeCache.size();
        int expired = 0;
        int authCount = 0;
        int registerCount = 0;
        int otherCount = 0;

        for (String key : challengeCache.keySet()) {
            ChallengeData data = challengeCache.get(key);
            if (data != null) {
                if (data.isExpired()) {
                    expired++;
                }

                if (key.startsWith("auth:")) {
                    authCount++;
                } else if (key.startsWith("register:")) {
                    registerCount++;
                } else {
                    otherCount++;
                }
            }
        }

        return String.format("Cache stats - Total: %d, Expired: %d, Active: %d (Auth: %d, Register: %d, Other: %d)",
                total, expired, total - expired, authCount, registerCount, otherCount);
    }

    /**
     * Clear all expired challenges manually
     */
    public static void cleanupExpiredChallenges() {
        long now = System.currentTimeMillis();
        int removedCount = 0;

        var iterator = challengeCache.entrySet().iterator();
        while (iterator.hasNext()) {
            var entry = iterator.next();
            if (now - entry.getValue().timestamp > 300000) {
                iterator.remove();
                removedCount++;
            }
        }

        if (removedCount > 0) {
            ServicesLogger.LOGGER.info("Cleaned up " + removedCount + " expired challenges");
        }
    }
}