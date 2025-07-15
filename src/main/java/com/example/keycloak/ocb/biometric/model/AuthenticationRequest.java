package com.example.keycloak.ocb.biometric.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AuthenticationRequest {
    @JsonProperty("credentialId")
    public String credentialId;

    @JsonProperty("clientDataJSON")
    public String clientDataJSON;

    @JsonProperty("authenticatorData")
    public String authenticatorData;

    @JsonProperty("signature")
    public String signature;

    @JsonProperty("userHandle")
    public String userHandle;
}