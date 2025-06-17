package com.example.keycloak.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CredentialData {
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
}