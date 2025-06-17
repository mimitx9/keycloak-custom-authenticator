package com.example.keycloak.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class AuthenticationOptions {
    @JsonProperty("challenge")
    public String challenge;

    @JsonProperty("rpId")
    public String rpId;

    @JsonProperty("allowedCredentials")
    public List<AllowedCredential> allowedCredentials;

    @JsonProperty("userVerificationRequirement")
    public String userVerificationRequirement;

    @JsonProperty("timeout")
    public int timeout;
}