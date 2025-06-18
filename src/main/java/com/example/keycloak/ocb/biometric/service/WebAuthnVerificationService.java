package com.example.keycloak.ocb.biometric.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.example.keycloak.model.AuthenticationRequest;
import com.example.keycloak.model.CredentialData;
import org.keycloak.services.ServicesLogger;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;
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
            ServicesLogger.LOGGER.error("Challenge validation failed", e);
            return false;
        }
    }

    public String extractPublicKeyFromAttestation(String attestationObject) {
        try {
            byte[] attestationBytes = Base64.getUrlDecoder().decode(attestationObject);

            String attestationString = new String(attestationBytes);
            if (attestationString.startsWith("webauthn-pubkey:")) {
                String publicKeyB64 = attestationString.substring("webauthn-pubkey:".length());
                ServicesLogger.LOGGER.info("Extracted public key from attestation");
                return publicKeyB64;
            }

            // If not in expected format, throw error
            throw new RuntimeException("Attestation object format not supported. Expected format: 'webauthn-pubkey:' + base64PublicKey");

        } catch (Exception e) {
            ServicesLogger.LOGGER.error("Failed to extract public key from attestation", e);
            throw new RuntimeException("Failed to extract public key: " + e.getMessage(), e);
        }
    }

    public boolean verifySignature(AuthenticationRequest request, CredentialData credential, String expectedChallenge) {
        try {
            ServicesLogger.LOGGER.info("Starting signature verification");

            // 1. Validate challenge first
            if (!validateChallenge(request.clientDataJSON, expectedChallenge)) {
                ServicesLogger.LOGGER.warn("Challenge validation failed");
                return false;
            }

            // 2. Validate required fields
            if (request.signature == null || request.signature.isEmpty()) {
                ServicesLogger.LOGGER.warn("Signature is null or empty");
                return false;
            }

            if (request.authenticatorData == null || request.authenticatorData.isEmpty()) {
                ServicesLogger.LOGGER.warn("Authenticator data is null or empty");
                return false;
            }

            // 3. Reconstruct signed data according to WebAuthn spec
            // signedData = authenticatorData || hash(clientDataJSON)
            byte[] clientDataBytes = Base64.getUrlDecoder().decode(request.clientDataJSON);
            byte[] clientDataHash = MessageDigest.getInstance("SHA-256").digest(clientDataBytes);
            byte[] authenticatorData = Base64.getUrlDecoder().decode(request.authenticatorData);

            byte[] signedData = new byte[authenticatorData.length + clientDataHash.length];
            System.arraycopy(authenticatorData, 0, signedData, 0, authenticatorData.length);
            System.arraycopy(clientDataHash, 0, signedData, authenticatorData.length, clientDataHash.length);

            ServicesLogger.LOGGER.info("Signed data length: " + signedData.length);

            // 4. Parse stored public key
            byte[] publicKeyBytes = Base64.getDecoder().decode(credential.publicKey);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            ServicesLogger.LOGGER.info("Public key algorithm: " + publicKey.getAlgorithm());

            // 5. Verify signature
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(publicKey);
            verifier.update(signedData);

            byte[] signatureBytes = Base64.getUrlDecoder().decode(request.signature);
            boolean result = verifier.verify(signatureBytes);

            ServicesLogger.LOGGER.info("Signature verification result: " + result);
            return result;

        } catch (Exception e) {
            ServicesLogger.LOGGER.error("Signature verification failed: " + e.getMessage(), e);
            return false;
        }
    }
}