package com.example.keycloak.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class RegistrationOptions {
    @JsonProperty("challenge")
    public String challenge;

    @JsonProperty("userid")
    public String userid;

    @JsonProperty("username")
    public String username;

    @JsonProperty("signatureAlgorithms")
    public List<Integer> signatureAlgorithms;

    @JsonProperty("rpEntityName")
    public String rpEntityName;

    @JsonProperty("rpId")
    public String rpId;

    @JsonProperty("createTimeout")
    public int createTimeout;

    @JsonProperty("attestationConveyancePreference")
    public String attestationConveyancePreference;

    @JsonProperty("authenticatorAttachment")
    public String authenticatorAttachment;

    @JsonProperty("userVerificationRequirement")
    public String userVerificationRequirement;

    @JsonProperty("requireResidentKey")
    public String requireResidentKey;
}