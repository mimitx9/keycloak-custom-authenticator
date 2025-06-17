package com.example.keycloak.ocb.biometric.service;

import java.security.SecureRandom;
import java.util.Base64;

public class ChallengeService {
    private static final SecureRandom secureRandom = new SecureRandom();

    public static String generateChallenge() {
        byte[] challenge = new byte[32];
        secureRandom.nextBytes(challenge);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(challenge);
    }
}