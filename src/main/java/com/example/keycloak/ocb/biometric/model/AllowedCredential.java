package com.example.keycloak.ocb.biometric.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class AllowedCredential {
    @JsonProperty("type")
    public String type = "public-key";

    @JsonProperty("id")
    public String id;

    @JsonProperty("transports")
    public List<String> transports;

    public AllowedCredential(String credentialId, List<String> transports) {
        this.id = credentialId;
        this.transports = transports;
    }
}