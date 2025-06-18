package com.example.keycloak.ocb.biometric;

import com.example.keycloak.model.*;
import com.example.keycloak.ocb.biometric.service.ChallengeCacheService;
import com.example.keycloak.ocb.biometric.service.ChallengeService;
import com.example.keycloak.ocb.biometric.service.WebAuthnCredentialService;
import com.example.keycloak.ocb.biometric.service.WebAuthnVerificationService;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import org.keycloak.TokenVerifier;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.Urls;
import org.keycloak.util.JsonSerialization;

import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.util.Arrays;
import java.util.Base64;
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
            RealmModel realm = session.realms().getRealmByName(realmName);
            if (realm == null) {
                return Response.status(404).entity("{\"error\":\"Realm not found: " + realmName + "\"}").build();
            }

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

            ChallengeCacheService.storeRegistrationChallenge(options.challenge, user.getUsername(), user.getId());

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
            RealmModel realm = session.realms().getRealmByName(realmName);
            if (realm == null) {
                return Response.status(404).entity("{\"error\":\"Realm not found: " + realmName + "\"}").build();
            }

            session.getContext().setRealm(realm);

            UserModel user = validateToken(authHeader, realm);
            if (user == null) {
                return Response.status(401).entity("{\"error\":\"Invalid token\"}").build();
            }

            ChallengeCacheService.ChallengeData challengeData = ChallengeCacheService.getRegistrationChallenge(user.getId());
            if (challengeData == null) {
                challengeData = ChallengeCacheService.getRegistrationChallengeByUsername(user.getUsername());
            }

            if (challengeData == null) {
                return Response.status(400).entity("{\"error\":\"Invalid session or expired challenge\"}").build();
            }

            String expectedChallenge = challengeData.challenge;
            ServicesLogger.LOGGER.info("Found registration challenge in cache: " + expectedChallenge);

            if (!verificationService.validateChallenge(request.clientDataJSON, expectedChallenge)) {
                return Response.status(400).entity("{\"error\":\"Invalid challenge\"}").build();
            }

            String publicKey = verificationService.extractPublicKeyFromAttestation(request.attestationObject);

            CredentialData credentialData = new CredentialData();
            credentialData.credentialId = request.publicKeyCredentialId; // Set credential ID từ request
            credentialData.publicKey = publicKey;
            credentialData.label = request.authenticatorLabel != null ?
                    request.authenticatorLabel : "Mobile Device";
            credentialData.transports = request.transports != null ?
                    request.transports : "internal";
            credentialData.createdAt = System.currentTimeMillis();
            credentialData.algorithm = -7;

            String savedCredentialId = credentialService.saveCredential(user, request.publicKeyCredentialId, credentialData);

            ChallengeCacheService.clearRegistrationChallenge(user.getId());

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

            if (credential.signatureCounter != null) {
                credentialService.updateCredentialCounter(credentialUser, request.credentialId, credential.signatureCounter);
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
        UriInfo uriInfo = session.getContext().getUri();
        if (uriInfo != null) {
            return uriInfo.getBaseUri().getHost();
        }
        return "localhost";
    }


    private TokenResponse createTokens(UserModel user, RealmModel realm) {
        try {
            long now = Time.currentTime();
            long exp = now + realm.getAccessTokenLifespan();

            Map<String, Object> accessTokenClaims = new HashMap<>();
            accessTokenClaims.put("iss", Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
            accessTokenClaims.put("sub", user.getId());
            accessTokenClaims.put("aud", "account");
            accessTokenClaims.put("exp", exp);
            accessTokenClaims.put("iat", now);
            accessTokenClaims.put("jti", KeycloakModelUtils.generateId());
            accessTokenClaims.put("preferred_username", user.getUsername());
            accessTokenClaims.put("email", user.getEmail());
            accessTokenClaims.put("scope", "openid profile email");
            accessTokenClaims.put("typ", "Bearer");

            Map<String, Object> refreshTokenClaims = new HashMap<>();
            refreshTokenClaims.put("iss", Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
            refreshTokenClaims.put("sub", user.getId());
            refreshTokenClaims.put("aud", "account");
            refreshTokenClaims.put("exp", now + realm.getRefreshTokenMaxReuse());
            refreshTokenClaims.put("iat", now);
            refreshTokenClaims.put("jti", KeycloakModelUtils.generateId());
            refreshTokenClaims.put("typ", "Refresh");

            String accessToken = createSimpleJWT(accessTokenClaims, realm);
            String refreshToken = createSimpleJWT(refreshTokenClaims, realm);

            TokenResponse response = new TokenResponse();
            response.accessToken = accessToken;
            response.refreshToken = refreshToken;
            response.expiresIn = (int) realm.getAccessTokenLifespan();
            response.tokenType = "Bearer";
            response.scope = "openid profile email";

            ServicesLogger.LOGGER.info("Created JWT tokens for user: " + user.getUsername());
            return response;

        } catch (Exception e) {
            ServicesLogger.LOGGER.error("Failed to create tokens for user: " + user.getUsername(), e);
            throw new RuntimeException("Token creation failed: " + e.getMessage(), e);
        }
    }

    private String createSimpleJWT(Map<String, Object> claims, RealmModel realm) {
        try {
            KeyManager.ActiveRsaKey activeKey = session.keys().getActiveRsaKey(realm);
            if (activeKey == null) {
                throw new RuntimeException("No RSA key available");
            }

            Map<String, Object> header = new HashMap<>();
            header.put("alg", "RS256");
            header.put("typ", "JWT");
            header.put("kid", activeKey.getKid());

            String encodedHeader = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(JsonSerialization.writeValueAsString(header).getBytes(StandardCharsets.UTF_8));

            String encodedPayload = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(JsonSerialization.writeValueAsString(claims).getBytes(StandardCharsets.UTF_8));

            String signingInput = encodedHeader + "." + encodedPayload;
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(activeKey.getPrivateKey());
            signer.update(signingInput.getBytes(StandardCharsets.UTF_8));

            String signature = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(signer.sign());

            return signingInput + "." + signature;

        } catch (Exception e) {
            throw new RuntimeException("JWT creation failed: " + e.getMessage(), e);
        }
    }
}