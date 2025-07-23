package com.example.keycloak.ocb.biometric.service;

import org.keycloak.services.ServicesLogger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.cache.CacheRealmProvider;
import org.keycloak.models.cache.CacheRealmProviderFactory;

import java.util.concurrent.ConcurrentHashMap;


public class ChallengeCacheService {

    private static final ConcurrentHashMap<String, ChallengeData> challengeCache =
            new ConcurrentHashMap<>(1000);

    private static final long CHALLENGE_EXPIRY_MS = 300000;
    private static final int MAX_CACHE_SIZE = 10000;

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
            return (System.currentTimeMillis() - timestamp) > CHALLENGE_EXPIRY_MS;
        }
    }
    private static void cleanupExpiredEntries() {
        if (challengeCache.size() > MAX_CACHE_SIZE * 0.8) { // Cleanup when 80% full
            long now = System.currentTimeMillis();
            challengeCache.entrySet().removeIf(entry ->
                    now - entry.getValue().timestamp > CHALLENGE_EXPIRY_MS);

            ServicesLogger.LOGGER.debug("Cleaned up expired cache entries. Current size: " + challengeCache.size());
        }
    }

    public static void storeRegistrationChallenge(String challenge, String username, String userId) {
        if (challenge == null || username == null || userId == null) {
            ServicesLogger.LOGGER.warn("Invalid parameters for storing registration challenge");
            return;
        }

        cleanupExpiredEntries();

        String challengeKey = "register:" + userId;
        ChallengeData data = new ChallengeData(challenge, username, userId);
        challengeCache.put(challengeKey, data);

        ServicesLogger.LOGGER.info("Stored registration challenge in cache for user: " + username);
    }

    public static ChallengeData getRegistrationChallenge(String userId) {
        if (userId == null) {
            ServicesLogger.LOGGER.warn("UserId is null when retrieving registration challenge");
            return null;
        }

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
        if (username == null) {
            ServicesLogger.LOGGER.warn("Username is null when retrieving registration challenge");
            return null;
        }

        // More efficient iteration using entrySet
        for (ConcurrentHashMap.Entry<String, ChallengeData> entry : challengeCache.entrySet()) {
            String key = entry.getKey();
            if (key.startsWith("register:")) {
                ChallengeData data = entry.getValue();
                if (data != null && username.equals(data.username)) {
                    if (data.isExpired()) {
                        challengeCache.remove(key);
                        continue;
                    }
                    ServicesLogger.LOGGER.info("Found registration challenge by username: " + username);
                    return data;
                }
            }
        }

        ServicesLogger.LOGGER.warn("No registration challenge found for username: " + username);
        return null;
    }

    public static void clearRegistrationChallenge(String userId) {
        if (userId == null) {
            ServicesLogger.LOGGER.warn("UserId is null when clearing registration challenge");
            return;
        }

        String challengeKey = "register:" + userId;
        ChallengeData removed = challengeCache.remove(challengeKey);

        if (removed != null) {
            ServicesLogger.LOGGER.info("Cleared registration challenge for user: " + removed.username);
        }
    }

    public static void storeChallengeForUser(String challenge, String username, String userId) {
        if (challenge == null || username == null || userId == null) {
            ServicesLogger.LOGGER.warn("Invalid parameters for storing auth challenge");
            return;
        }

        cleanupExpiredEntries();

        String challengeKey = "auth:" + userId;
        ChallengeData data = new ChallengeData(challenge, username, userId);
        challengeCache.put(challengeKey, data);

        ServicesLogger.LOGGER.info("Stored auth challenge in cache for user: " + username);
    }

    public static ChallengeData getAuthChallenge(String userId) {
        if (userId == null) {
            ServicesLogger.LOGGER.warn("UserId is null when retrieving auth challenge");
            return null;
        }

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


    public static ChallengeData getAuthChallengeByUsername(String username) {
        if (username == null) {
            ServicesLogger.LOGGER.warn("Username is null when retrieving auth challenge");
            return null;
        }

        for (ConcurrentHashMap.Entry<String, ChallengeData> entry : challengeCache.entrySet()) {
            String key = entry.getKey();
            if (key.startsWith("auth:")) {
                ChallengeData data = entry.getValue();
                if (data != null && username.equals(data.username)) {
                    if (data.isExpired()) {
                        challengeCache.remove(key);
                        continue;
                    }
                    ServicesLogger.LOGGER.info("Found auth challenge by username: " + username);
                    return data;
                }
            }
        }

        ServicesLogger.LOGGER.warn("No auth challenge found for username: " + username);
        return null;
    }

    public static void clearAuthChallenge(String userId) {
        if (userId == null) {
            ServicesLogger.LOGGER.warn("UserId is null when clearing auth challenge");
            return;
        }

        String challengeKey = "auth:" + userId;
        ChallengeData removed = challengeCache.remove(challengeKey);

        if (removed != null) {
            ServicesLogger.LOGGER.info("Cleared auth challenge for user: " + removed.username);
        }
    }
}