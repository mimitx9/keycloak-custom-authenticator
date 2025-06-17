package com.example.keycloak.ocb.biometric.service;


import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.example.keycloak.model.AuthenticationRequest;
import com.example.keycloak.model.CredentialData;

import java.util.Base64;

public class WebAuthnVerificationService {
    private final ObjectMapper objectMapper = new ObjectMapper();

    public boolean validateChallenge(String clientDataJSON, String expectedChallenge) {
        try {
            byte[] clientDataBytes = Base64.getUrlDecoder().decode(clientDataJSON);
            String clientDataString = new String(clientDataBytes);
            JsonNode clientData = objectMapper.readTree(clientDataString);

            String receivedChallenge = clientData.get("challenge").asText();
            return expectedChallenge.equals(receivedChallenge);
        } catch (Exception e) {
            return false;
        }
    }

    public String extractPublicKeyFromAttestation(String attestationObject) {
        // This is a simplified version - in production you'd need proper CBOR parsing
        // For now, return a placeholder that mobile apps can work with
        try {
            byte[] attestationBytes = Base64.getUrlDecoder().decode(attestationObject);
            // In real implementation, parse CBOR and extract public key
            // For demo purposes, return base64 of attestation
            return Base64.getEncoder().encodeToString(attestationBytes);
        } catch (Exception e) {
            throw new RuntimeException("Failed to extract public key", e);
        }
    }

    public boolean verifySignature(AuthenticationRequest request, CredentialData credential, String expectedChallenge) {
        // Simplified verification - in production implement proper signature verification
        try {
            // 1. Validate challenge
            if (!validateChallenge(request.clientDataJSON, expectedChallenge)) {
                return false;
            }

            // 2. For demo purposes, accept any signature if challenge is valid
            // In production: verify signature using stored public key
            return request.signature != null && !request.signature.isEmpty();

        } catch (Exception e) {
            return false;
        }
    }
}