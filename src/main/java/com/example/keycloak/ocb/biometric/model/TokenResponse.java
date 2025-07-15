package com.example.keycloak.ocb.biometric.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class TokenResponse {
    @JsonProperty("access_token")
    public String accessToken;

    @JsonProperty("refresh_token")
    public String refreshToken;

    @JsonProperty("expires_in")
    public long expiresIn;

    @JsonProperty("token_type")
    public String tokenType = "Bearer";
    @JsonProperty("scope")
    public String scope;
    @JsonProperty("session_state")
    public String sessionState;
}