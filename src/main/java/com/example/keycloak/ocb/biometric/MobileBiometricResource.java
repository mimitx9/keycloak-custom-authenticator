package com.example.keycloak.ocb.biometric;

import com.example.keycloak.model.*;
import com.example.keycloak.ocb.biometric.service.ChallengeCacheService;
import com.example.keycloak.ocb.biometric.service.ChallengeService;
import com.example.keycloak.ocb.biometric.service.WebAuthnCredentialService;
import com.example.keycloak.ocb.biometric.service.WebAuthnVerificationService;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import org.keycloak.TokenVerifier;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.Urls;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

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
    @Path("/debug")
    @Produces(MediaType.APPLICATION_JSON)
    public Response debug(@PathParam("realm") String realmName) {
        try {
            Map<String, Object> debugInfo = new HashMap<>();
            debugInfo.put("pathRealmName", realmName);

            // Test realm lookup
            RealmModel realm = session.realms().getRealmByName(realmName);
            debugInfo.put("realmFound", realm != null);

            if (realm != null) {
                debugInfo.put("realmDisplayName", realm.getDisplayName());
                debugInfo.put("realmEnabled", realm.isEnabled());
            }

            // Test context realm
            RealmModel contextRealm = session.getContext().getRealm();
            debugInfo.put("contextRealmFound", contextRealm != null);

            if (contextRealm != null) {
                debugInfo.put("contextRealmName", contextRealm.getName());
            }

            // List all realms
            List<String> allRealms = session.realms().getRealmsStream()
                    .map(RealmModel::getName)
                    .collect(Collectors.toList());
            debugInfo.put("allRealms", allRealms);

            debugInfo.put("status", "extension working");
            debugInfo.put("timestamp", System.currentTimeMillis());

            return Response.ok(debugInfo).build();

        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            error.put("stackTrace", Arrays.toString(e.getStackTrace()));
            return Response.status(500).entity(error).build();
        }
    }

    @GET
    @Path("/register/init")
    @Produces(MediaType.APPLICATION_JSON)
    public Response initRegistration(@PathParam("realm") String realmName,
                                     @HeaderParam("Authorization") String authHeader,
                                     @Context HttpHeaders headers) {

        try {
            // Fix: Lấy realm từ realmName path parameter
            RealmModel realm = session.realms().getRealmByName(realmName);
            if (realm == null) {
                return Response.status(404).entity("{\"error\":\"Realm not found: " + realmName + "\"}").build();
            }

            // Set realm context
            session.getContext().setRealm(realm);

            UserModel user = validateToken(authHeader, realm);
            if (user == null) {
                return Response.status(401).entity("{\"error\":\"Invalid token\"}").build();
            }

            RegistrationOptions options = new RegistrationOptions();
            options.challenge = ChallengeService.generateChallenge();
            options.userid = java.util.Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(user.getId().getBytes());
            options.username = user.getUsername();
            options.signatureAlgorithms = Arrays.asList(-7, -257);
            options.rpEntityName = realm.getDisplayName() != null ? realm.getDisplayName() : realm.getName();
            options.rpId = getRealmHostname(realm);
            options.createTimeout = 60000;
            options.attestationConveyancePreference = "none";
            options.authenticatorAttachment = "platform";
            options.userVerificationRequirement = "required";
            options.requireResidentKey = "false";
            storeChallenge(user, options.challenge);

            return Response.ok(options).build();

        } catch (Exception e) {
            ServicesLogger.LOGGER.error("Error in registration init", e);
            return Response.status(500).entity("{\"error\":\"Internal server error: " + e.getMessage() + "\"}").build();
        }
    }

    @POST
    @Path("/register/complete")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response completeRegistration(@PathParam("realm") String realmName,
                                         RegistrationRequest request,
                                         @HeaderParam("Authorization") String authHeader) {

        try {
            // Fix: Lấy realm từ realmName path parameter
            RealmModel realm = session.realms().getRealmByName(realmName);
            if (realm == null) {
                return Response.status(404).entity("{\"error\":\"Realm not found: " + realmName + "\"}").build();
            }

            // Set realm context
            session.getContext().setRealm(realm);

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

            CredentialData credentialData = new CredentialData();
            credentialData.publicKey = publicKey;
            credentialData.label = request.authenticatorLabel != null ?
                    request.authenticatorLabel : "Mobile Device";
            credentialData.transports = request.transports != null ?
                    request.transports : "internal";
            credentialData.createdAt = System.currentTimeMillis();
            credentialData.algorithm = -7; // ES256 default

            // Save credential
            String savedCredentialId = credentialService.saveCredential(user, request.publicKeyCredentialId, credentialData);

            // Clear challenge
            clearChallenge(user);

            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("credentialId", request.publicKeyCredentialId);
            response.put("keycloakCredentialId", savedCredentialId);

            return Response.ok(response).build();

        } catch (Exception e) {
            ServicesLogger.LOGGER.error("Error in registration complete", e);
            return Response.status(500).entity("{\"error\":\"Internal server error: " + e.getMessage() + "\"}").build();
        }
    }

    @GET
    @Path("/authenticate/init")
    @Produces(MediaType.APPLICATION_JSON)
    public Response initAuthentication(@PathParam("realm") String realmName,
                                       @QueryParam("username") String username) {

        try {
            RealmModel realm = session.realms().getRealmByName(realmName);
            if (realm == null) {
                return Response.status(404).entity("{\"error\":\"Realm not found: " + realmName + "\"}").build();
            }

            session.getContext().setRealm(realm);

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

            ChallengeCacheService.storeChallengeForUser(options.challenge, username, user.getId());

            return Response.ok(options).build();

        } catch (Exception e) {
            ServicesLogger.LOGGER.error("Error in authentication init", e);
            return Response.status(500).entity("{\"error\":\"Internal server error: " + e.getMessage() + "\"}").build();
        }
    }

    @POST
    @Path("/authenticate/complete")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response completeAuthentication(@PathParam("realm") String realmName,
                                           @QueryParam("username") String username,
                                           AuthenticationRequest request) {

        try {
            RealmModel realm = session.realms().getRealmByName(realmName);
            if (realm == null) {
                return Response.status(404).entity("{\"error\":\"Realm not found: " + realmName + "\"}").build();
            }

            session.getContext().setRealm(realm);

            ServicesLogger.LOGGER.info("Looking for challenge for credential: " + request.credentialId);
            String userId = null;

            UserModel credentialUser = session.users().getUserByUsername(realm, username);
            if (credentialUser != null) {
                userId = credentialUser.getId();
                ServicesLogger.LOGGER.info("Found user by provided username: " + username);
            }

            ServicesLogger.LOGGER.info("Found user by credential: " + username);

            // Get challenge from cache
            ChallengeCacheService.ChallengeData challengeData = ChallengeCacheService.getAuthChallenge(userId);
            if (challengeData == null) {
                challengeData = ChallengeCacheService.getAuthChallengeByUsername(username);
            }

            if (challengeData == null) {
                return Response.status(400).entity("{\"error\":\"Invalid session or expired challenge\"}").build();
            }

            String expectedChallenge = challengeData.challenge;
            ServicesLogger.LOGGER.info("Found challenge in cache: " + expectedChallenge);

            CredentialData credential = credentialService.getCredential(credentialUser, request.credentialId);
            if (credential == null) {
                return Response.status(404).entity("{\"error\":\"Credential not found\"}").build();
            }

            if (!verificationService.verifySignature(request, credential, expectedChallenge)) {
                return Response.status(401).entity("{\"error\":\"Authentication failed\"}").build();
            }

            TokenResponse tokenResponse = createTokens(credentialUser, realm);
            ChallengeCacheService.clearAuthChallenge(userId);

            return Response.ok(tokenResponse).build();

        } catch (Exception e) {
            ServicesLogger.LOGGER.error("Error in authentication complete", e);
            return Response.status(500).entity("{\"error\":\"Internal server error: " + e.getMessage() + "\"}").build();
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

            TokenVerifier<AccessToken> verifier = TokenVerifier.create(tokenString, AccessToken.class).realmUrl(Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName())).checkActive(true).checkTokenType(true).publicKey(activeKey.getPublicKey());

            AccessToken token = verifier.verify().getToken();
            return session.users().getUserById(realm, token.getSubject());

        } catch (Exception e) {
            ServicesLogger.LOGGER.warn("Token validation failed", e);
            return null;
        }
    }

    private String getRealmHostname(RealmModel realm) {
        // Get hostname from current request context
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

    private TokenResponse createTokens(UserModel user, RealmModel realm) {
        TokenResponse response = new TokenResponse();
        response.accessToken = "mock_access_token_" + user.getId();
        response.refreshToken = "mock_refresh_token_" + user.getId();
        response.expiresIn = 3600;
        return response;
    }
}