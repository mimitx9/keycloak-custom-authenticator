package com.example.keycloak.ocb.biometric;

import com.example.keycloak.model.*;
import com.example.keycloak.ocb.biometric.service.*;
import org.keycloak.TokenVerifier;
import org.keycloak.models.*;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.common.ClientConnection;
import org.keycloak.headers.SecurityHeadersProvider;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.ResourceAdminManager;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@Path("/realms/{realm}/mobile-biometric")
public class MobileBiometricResource {

    private final KeycloakSession session;
    private final WebAuthnCredentialService credentialService;
    private final WebAuthnVerificationService verificationService;

    public MobileBiometricResource(KeycloakSession session) {
        this.session = session;
        this.credentialService = new WebAuthnCredentialService();
        this.verificationService = new WebAuthnVerificationService();
    }

    @GET
    @Path("/register/init")
    @Produces(MediaType.APPLICATION_JSON)
    public Response initRegistration(@PathParam("realm") String realmName,
                                     @HeaderParam("Authorization") String authHeader,
                                     @Context HttpHeaders headers) {

        try {
            RealmModel realm = session.getContext().getRealm();
            if (realm == null) {
                return Response.status(404).entity("{\"error\":\"Realm not found\"}").build();
            }

            UserModel user = validateToken(authHeader, realm);
            if (user == null) {
                return Response.status(401).entity("{\"error\":\"Invalid token\"}").build();
            }

            RegistrationOptions options = new RegistrationOptions();
            options.challenge = ChallengeService.generateChallenge();
            options.userid = java.util.Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(user.getId().getBytes());
            options.username = user.getUsername();
            options.signatureAlgorithms = Arrays.asList(-7, -257); // ES256, RS256
            options.rpEntityName = realm.getDisplayName() != null ? realm.getDisplayName() : realm.getName();
            options.rpId = getRealmHostname(realm);
            options.createTimeout = 60000;
            options.attestationConveyancePreference = "none";
            options.authenticatorAttachment = "platform";
            options.userVerificationRequirement = "required";
            options.requireResidentKey = "false";

            // Store challenge in user session
            storeChallenge(user, options.challenge);

            return Response.ok(options).build();

        } catch (Exception e) {
            ServicesLogger.LOGGER.error("Error in registration init", e);
            return Response.status(500).entity("{\"error\":\"Internal server error\"}").build();
        }
    }

// Cập nhật trong MobileBiometricResource.java

    @POST
    @Path("/register/complete")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response completeRegistration(@PathParam("realm") String realmName,
                                         RegistrationRequest request,
                                         @HeaderParam("Authorization") String authHeader) {

        try {
            RealmModel realm = session.getContext().getRealm();
            UserModel user = validateToken(authHeader, realm);
            if (user == null) {
                return Response.status(401).entity("{\"error\":\"Invalid token\"}").build();
            }

            // Validate challenge
            String expectedChallenge = getStoredChallenge(user);
            if (expectedChallenge == null ||
                    !verificationService.validateChallenge(request.clientDataJSON, expectedChallenge)) {
                return Response.status(400).entity("{\"error\":\"Invalid challenge\"}").build();
            }

            // Extract public key from attestation
            String publicKey = verificationService.extractPublicKeyFromAttestation(request.attestationObject);

            // Create credential data
            CredentialData credentialData = new CredentialData();
            credentialData.publicKey = publicKey;
            credentialData.label = request.authenticatorLabel != null ?
                    request.authenticatorLabel : "Mobile Device";
            credentialData.transports = request.transports != null ?
                    request.transports : "internal";
            credentialData.createdAt = System.currentTimeMillis();
            credentialData.algorithm = -7; // ES256 default

            String savedCredentialId = credentialService.saveCredential(user, request.publicKeyCredentialId, credentialData);

            // Clear challenge
            clearChallenge(user);

            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("credentialId", request.publicKeyCredentialId);
            response.put("keycloakCredentialId", savedCredentialId); // ID trong Keycloak store

            return Response.ok(response).build();

        } catch (Exception e) {
            ServicesLogger.LOGGER.error("Error in registration complete", e);
            return Response.status(500).entity("{\"error\":\"Internal server error\"}").build();
        }
    }

    @GET
    @Path("/authenticate/init")
    @Produces(MediaType.APPLICATION_JSON)
    public Response initAuthentication(@PathParam("realm") String realmName,
                                       @QueryParam("username") String username) {

        try {
            RealmModel realm = session.getContext().getRealm();
            if (realm == null) {
                return Response.status(404).entity("{\"error\":\"Realm not found\"}").build();
            }

            UserModel user = session.users().getUserByUsername(realm, username);
            if (user == null) {
                return Response.status(404).entity("{\"error\":\"User not found\"}").build();
            }

            var allowedCredentials = credentialService.getAllowedCredentials(user);
            if (allowedCredentials.isEmpty()) {
                return Response.status(404).entity("{\"error\":\"No credentials found\"}").build();
            }

            AuthenticationOptions options = new AuthenticationOptions();
            options.challenge = ChallengeService.generateChallenge();
            options.rpId = getRealmHostname(realm);
            options.allowedCredentials = allowedCredentials;
            options.userVerificationRequirement = "required";
            options.timeout = 60000;

            storeAuthChallenge(options.challenge, username);

            return Response.ok(options).build();

        } catch (Exception e) {
            ServicesLogger.LOGGER.error("Error in authentication init", e);
            return Response.status(500).entity("{\"error\":\"Internal server error\"}").build();
        }
    }

    @POST
    @Path("/authenticate/complete")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response completeAuthentication(@PathParam("realm") String realmName,
                                           AuthenticationRequest request) {

        try {
            RealmModel realm = session.getContext().getRealm();

            // Get stored challenge and username
            String[] challengeData = getStoredAuthChallenge();
            if (challengeData == null) {
                return Response.status(400).entity("{\"error\":\"Invalid session\"}").build();
            }

            String expectedChallenge = challengeData[0];
            String username = challengeData[1];

            UserModel user = session.users().getUserByUsername(realm, username);
            if (user == null) {
                return Response.status(404).entity("{\"error\":\"User not found\"}").build();
            }

            CredentialData credential = credentialService.getCredential(user, request.credentialId);
            if (credential == null) {
                return Response.status(404).entity("{\"error\":\"Credential not found\"}").build();
            }

            if (!verificationService.verifySignature(request, credential, expectedChallenge)) {
                return Response.status(401).entity("{\"error\":\"Authentication failed\"}").build();
            }

            TokenResponse tokenResponse = createTokens(user, realm);

            clearAuthChallenge();

            return Response.ok(tokenResponse).build();

        } catch (Exception e) {
            ServicesLogger.LOGGER.error("Error in authentication complete", e);
            return Response.status(500).entity("{\"error\":\"Internal server error\"}").build();
        }
    }

    private UserModel validateToken(String authHeader, RealmModel realm) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return null;
        }
        try {
            String tokenString = authHeader.substring("Bearer ".length());
            KeyManager.ActiveRsaKey activeKey = session.keys().getActiveRsaKey(realm);
            if (activeKey == null) {
                ServicesLogger.LOGGER.warn("No active RSA key found for realm: " + realm.getName());
                return null;
            }

            TokenVerifier<AccessToken> verifier = TokenVerifier.create(tokenString, AccessToken.class)
                    .realmUrl(Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()))
                    .checkActive(true)
                    .checkTokenType(true)
                    .publicKey(activeKey.getPublicKey());

            AccessToken token = verifier.verify().getToken();
            return session.users().getUserById(realm, token.getSubject());

        } catch (Exception e) {
            ServicesLogger.LOGGER.warn("Token validation failed", e);
            return null;
        }
    }


    private String getRealmHostname(RealmModel realm) {
        UriInfo uriInfo = session.getContext().getUri();
        if (uriInfo != null) {
            return uriInfo.getBaseUri().getHost();
        }
        return "localhost"; // fallback
    }

    private void storeChallenge(UserModel user, String challenge) {
        user.setAttribute("webauthn.temp.challenge", Arrays.asList(challenge));
    }

    private String getStoredChallenge(UserModel user) {
        var challenges = user.getAttributes().get("webauthn.temp.challenge");
        return (challenges != null && !challenges.isEmpty()) ? challenges.get(0) : null;
    }

    private void clearChallenge(UserModel user) {
        user.removeAttribute("webauthn.temp.challenge");
    }

    private void storeAuthChallenge(String challenge, String username) {
        session.setAttribute("auth.challenge", challenge);
        session.setAttribute("auth.username", username);
    }

    private String[] getStoredAuthChallenge() {
        String challenge = (String) session.getAttribute("auth.challenge");
        String username = (String) session.getAttribute("auth.username");
        return (challenge != null && username != null) ? new String[]{challenge, username} : null;
    }

    private void clearAuthChallenge() {
        session.removeAttribute("auth.challenge");
        session.removeAttribute("auth.username");
    }

    private TokenResponse createTokens(UserModel user, RealmModel realm) {

        TokenResponse response = new TokenResponse();
        response.accessToken = "mock_access_token_" + user.getId();
        response.refreshToken = "mock_refresh_token_" + user.getId();
        response.expiresIn = 3600;
        return response;
    }
}