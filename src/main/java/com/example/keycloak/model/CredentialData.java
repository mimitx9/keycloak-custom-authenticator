package com.example.keycloak.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CredentialData {
    @JsonProperty("credentialId")
    public String credentialId;

    @JsonProperty("publicKey")
    public String publicKey;

    @JsonProperty("label")
    public String label;

    @JsonProperty("transports")
    public String transports;

    @JsonProperty("createdAt")
    public long createdAt;

    @JsonProperty("algorithm")
    public int algorithm;

    @JsonProperty("aaguid")
    public String aaguid;           // Authenticator AAGUID
    @JsonProperty("signatureCounter")
    public Long signatureCounter;   // Signature counter
    @JsonProperty("attestationFormat")
    public String attestationFormat; // Attestation format
}