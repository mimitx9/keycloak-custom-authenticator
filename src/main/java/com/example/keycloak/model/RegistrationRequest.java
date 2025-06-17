package com.example.keycloak.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class RegistrationRequest {
    @JsonProperty("clientDataJSON")
    public String clientDataJSON;

    @JsonProperty("attestationObject")
    public String attestationObject;

    @JsonProperty("publicKeyCredentialId")
    public String publicKeyCredentialId;

    @JsonProperty("authenticatorLabel")
    public String authenticatorLabel;

    @JsonProperty("transports")
    public String transports;
}