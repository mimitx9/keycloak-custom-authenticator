package com.example.keycloak.ocb.biometric.service;

import com.example.keycloak.ocb.biometric.model.AllowedCredential;
import com.example.keycloak.ocb.biometric.model.CredentialData;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.models.credential.dto.WebAuthnCredentialData;
import org.keycloak.models.credential.dto.WebAuthnSecretData;
import org.keycloak.services.ServicesLogger;
import org.keycloak.util.JsonSerialization;

import java.util.*;
import java.util.stream.Collectors;

public class WebAuthnCredentialService {

    public static final String CREDENTIAL_TYPE = WebAuthnCredentialModel.TYPE_PASSWORDLESS;

    public String saveCredential(UserModel user, String credentialId, CredentialData data) {
        try {
            WebAuthnCredentialData credentialData = getWebAuthnCredentialData(credentialId, data);

            WebAuthnSecretData secretData = new WebAuthnSecretData();

            CredentialModel credential = new CredentialModel();
            credential.setType(CREDENTIAL_TYPE);
            credential.setUserLabel(data.label != null ? data.label : "Mobile Device");
            credential.setCreatedDate(data.createdAt);

            credential.setCredentialData(JsonSerialization.writeValueAsString(credentialData));
            credential.setSecretData(JsonSerialization.writeValueAsString(secretData));

            CredentialModel savedCredential = user.credentialManager().createStoredCredential(credential);

            return savedCredential.getId();

        } catch (Exception e) {
            throw new RuntimeException("Failed to save WebAuthn credential", e);
        }
    }

    private static WebAuthnCredentialData getWebAuthnCredentialData(String credentialId, CredentialData data) {
        String aaguid = "00000000-0000-0000-0000-000000000000";
        long counter = 0;
        String attestationStatement = "{}";
        String attestationStatementFormat = "none";

        Set<String> transports;
        if (data.transports != null) {
            transports = new HashSet<>(Arrays.asList(data.transports.split(",")));
        } else {
            transports = new HashSet<>(List.of("internal"));
        }

        return new WebAuthnCredentialData(
                aaguid,
                credentialId,
                counter,
                attestationStatement,
                data.publicKey,
                attestationStatementFormat,
                transports
        );
    }

    public CredentialData getCredential(UserModel user, String credentialId) {
        List<CredentialModel> allCredentials = user.credentialManager().getStoredCredentialsStream().toList();
        List<CredentialModel> webAuthnCredentials = allCredentials.stream()
                .filter(cred -> CREDENTIAL_TYPE.equals(cred.getType()))
                .toList();

        for (CredentialModel credential : webAuthnCredentials) {
            try {
                WebAuthnCredentialData credData = JsonSerialization.readValue(
                        credential.getCredentialData(), WebAuthnCredentialData.class);

                if (credentialId.equals(credData.getCredentialId())) {
                    CredentialData data = new CredentialData();
                    data.publicKey = credData.getCredentialPublicKey();
                    data.label = credential.getUserLabel();
                    data.createdAt = credential.getCreatedDate();
                    data.algorithm = -7; // Default ES256

                    if (credData.getTransports() != null) {
                        data.transports = String.join(",", credData.getTransports());
                    }

                    return data;
                }
            } catch (Exception e) {
                ServicesLogger.LOGGER.error("Failed to parse WebAuthn credential data for credential ID: " + credentialId, e);
            }
        }

        return null;
    }

    public List<AllowedCredential> getAllowedCredentials(UserModel user) {
        List<CredentialModel> allCredentials = user.credentialManager().getStoredCredentialsStream().toList();
        List<CredentialModel> webAuthnCredentials = allCredentials.stream()
                .filter(cred -> CREDENTIAL_TYPE.equals(cred.getType()))
                .toList();

        return webAuthnCredentials.stream()
                .map(credential -> {
                    try {
                        WebAuthnCredentialData credData = JsonSerialization.readValue(
                                credential.getCredentialData(), WebAuthnCredentialData.class);

                        List<String> transports = credData.getTransports() != null ?
                                new ArrayList<>(credData.getTransports()) : List.of("internal");

                        return new AllowedCredential(credData.getCredentialId(), transports);

                    } catch (Exception e) {
                        // Return default nếu parse lỗi
                        return new AllowedCredential(credential.getId(), List.of("internal"));
                    }
                })
                .collect(Collectors.toList());
    }

    public void updateCredentialCounter(UserModel user, String credentialId, long newCounter) {
        try {
            List<CredentialModel> allCredentials = user.credentialManager().getStoredCredentialsStream().toList();
            List<CredentialModel> webAuthnCredentials = allCredentials.stream()
                    .filter(cred -> CREDENTIAL_TYPE.equals(cred.getType()))
                    .toList();

            for (CredentialModel credential : webAuthnCredentials) {
                try {
                    WebAuthnCredentialData credData = JsonSerialization.readValue(
                            credential.getCredentialData(), WebAuthnCredentialData.class);

                    if (credentialId.equals(credData.getCredentialId())) {
                        WebAuthnCredentialData updatedCredData = new WebAuthnCredentialData(
                                credData.getAaguid(),
                                credData.getCredentialId(),
                                newCounter,
                                credData.getAttestationStatement(),
                                credData.getCredentialPublicKey(),
                                credData.getAttestationStatementFormat(),
                                credData.getTransports()
                        );

                        credential.setCredentialData(JsonSerialization.writeValueAsString(updatedCredData));
                        user.credentialManager().updateStoredCredential(credential);

                        ServicesLogger.LOGGER.info("Updated counter for credential " + credentialId + " to " + newCounter);
                        return;
                    }
                } catch (Exception e) {
                    ServicesLogger.LOGGER.error("Failed to update credential counter", e);
                }
            }

        } catch (Exception e) {
            ServicesLogger.LOGGER.error("Failed to update credential counter", e);
        }
    }
}