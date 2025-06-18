package com.example.keycloak.ocb.biometric;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class MobileBiometricResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public MobileBiometricResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return new MobileBiometricResource(session);
    }

    @Override
    public void close() {
    }
}