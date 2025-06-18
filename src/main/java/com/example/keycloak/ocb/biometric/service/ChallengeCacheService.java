package com.example.keycloak.ocb.biometric.service;

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

    public static void storeRegistrationChallenge(String challenge, String username, String userId) {
        String challengeKey = "register:" + userId;
        ChallengeData data = new ChallengeData(challenge, username, userId);
        challengeCache.put(challengeKey, data);
        ServicesLogger.LOGGER.info("Stored registration challenge in cache for user: " + username);
    }

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

    public static ChallengeData getRegistrationChallengeByUsername(String username) {
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

    public static void clearRegistrationChallenge(String userId) {
        String challengeKey = "register:" + userId;
        ChallengeData removed = challengeCache.remove(challengeKey);

        if (removed != null) {
            ServicesLogger.LOGGER.info("Cleared registration challenge for user: " + removed.username);
        }
    }

    public static void storeChallengeForUser(String challenge, String username, String userId) {
        String challengeKey = "auth:" + userId;
        ChallengeData data = new ChallengeData(challenge, username, userId);
        challengeCache.put(challengeKey, data);
        ServicesLogger.LOGGER.info("Stored auth challenge in cache for user: " + username);
    }

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


    public static void clearAuthChallenge(String userId) {
        String challengeKey = "auth:" + userId;
        ChallengeData removed = challengeCache.remove(challengeKey);

        if (removed != null) {
            ServicesLogger.LOGGER.info("Cleared auth challenge for user: " + removed.username);
        }
    }
}