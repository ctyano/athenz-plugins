package com.yahoo.athenz.auth.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.auth.util.Crypto;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

public class OIDCJwtAuthorityTest {

    private final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");
    private final File oidcIssuerDir = new File("./src/test/resources/jwt-oidc");

    @AfterMethod
    public void clearProperties() {
        System.clearProperty(OIDCJwtAuthority.ATHENZ_PROP_OIDC_JWT_JWKS_URI);
        System.clearProperty(OIDCJwtAuthority.ATHENZ_PROP_OIDC_JWT_AUDIENCE);
        System.clearProperty(OIDCJwtAuthority.ATHENZ_PROP_OIDC_JWT_ISSUER);
        System.clearProperty(OIDCJwtAuthority.ATHENZ_PROP_OIDC_JWT_DOMAIN);
        System.clearProperty(OIDCJwtAuthority.ATHENZ_PROP_OIDC_JWT_BOOT_TIME_OFFSET);
        System.clearProperty(OIDCJwtAuthority.ATHENZ_PROP_OIDC_JWT_CLAIM);
        File configFile = new File(oidcIssuerDir, ".well-known/openid-configuration");
        if (configFile.exists()) {
            configFile.delete();
        }
    }

    @Test
    public void testGetters() {
        OIDCJwtAuthority authority = new OIDCJwtAuthority();
        assertEquals(authority.getID(), "Jwt");
        assertEquals(authority.getHeader(), "Authorization");
        assertEquals(authority.getAuthenticateChallenge(), "Bearer realm=\"athenz\"");
    }

    @Test
    public void testAuthenticateWithIssuerDiscovery() throws JOSEException, IOException {
        final String issuer = "file://" + oidcIssuerDir.getCanonicalPath();
        createOpenIdConfigFile(new File(oidcIssuerDir, ".well-known/openid-configuration"),
                new File("./src/test/resources/jwt_jwks.json"));
        System.setProperty(OIDCJwtAuthority.ATHENZ_PROP_OIDC_JWT_AUDIENCE, "https://athenz.io");
        System.setProperty(OIDCJwtAuthority.ATHENZ_PROP_OIDC_JWT_CLAIM, "repository");

        try (MockedConstruction<JwtsHelper> mockedHelpers = Mockito.mockConstruction(JwtsHelper.class,
                (mock, context) -> Mockito.when(mock.extractJwksUri(Mockito.anyString(), Mockito.isNull()))
                        .thenReturn("https://mock.oidc.example/jwks"));
             MockedConstruction<JwtsSigningKeyResolver> mockedResolvers = mockSigningKeyResolverConstruction()) {

            OIDCJwtAuthority authority = new OIDCJwtAuthority();
            authority.initialize();

            String token = "Bearer " + generateIdToken(issuer,
                    System.currentTimeMillis() / 1000, "athenz", "athenz/demo", false, false);

            StringBuilder errMsg = new StringBuilder();
            Principal principal = authority.authenticate(token, "127.0.0.1", "GET", errMsg);
            assertNotNull(principal);
            assertEquals(principal.getDomain(), "user");
            assertEquals(principal.getName(), "athenz/demo");
            assertEquals(errMsg.toString(), "");
        }
    }

    @Test
    public void testAuthenticateWithFallbackConfiguredJwksUri() throws JOSEException {
        final String jwksUri = Objects.requireNonNull(getClass().getClassLoader().getResource("jwt_jwks.json")).toString();
        System.setProperty(OIDCJwtAuthority.ATHENZ_PROP_OIDC_JWT_JWKS_URI, jwksUri);
        System.setProperty(OIDCJwtAuthority.ATHENZ_PROP_OIDC_JWT_AUDIENCE, "https://athenz.io");
        System.setProperty(OIDCJwtAuthority.ATHENZ_PROP_OIDC_JWT_CLAIM, "repository");
        AtomicReference<String> constructedJwksUri = new AtomicReference<>();

        try (MockedConstruction<JwtsHelper> mockedHelpers = Mockito.mockConstruction(JwtsHelper.class,
                (mock, context) -> Mockito.when(mock.extractJwksUri(Mockito.anyString(), Mockito.isNull()))
                        .thenReturn(null));
             MockedConstruction<JwtsSigningKeyResolver> mockedResolvers =
                     mockSigningKeyResolverConstruction(constructedJwksUri)) {

            OIDCJwtAuthority authority = new OIDCJwtAuthority();
            authority.initialize();

            String token = "Bearer " + generateIdToken("https://athenz-zts-server.athenz:4443/zts/v1",
                    System.currentTimeMillis() / 1000, "athenz", "athenz/demo", false, false);

            StringBuilder errMsg = new StringBuilder();
            Principal principal = authority.authenticate(token, "127.0.0.1", "GET", errMsg);
            assertNotNull(principal);
            assertEquals(principal.getName(), "athenz/demo");
            assertEquals(errMsg.toString(), "");
            assertEquals(mockedResolvers.constructed().size(), 1);
            assertEquals(constructedJwksUri.get(), jwksUri);
        }
    }

    @Test
    public void testAuthenticateIssuerMismatch() throws JOSEException {
        final String jwksUri = Objects.requireNonNull(getClass().getClassLoader().getResource("jwt_jwks.json")).toString();
        System.setProperty(OIDCJwtAuthority.ATHENZ_PROP_OIDC_JWT_JWKS_URI, jwksUri);
        System.setProperty(OIDCJwtAuthority.ATHENZ_PROP_OIDC_JWT_AUDIENCE, "https://athenz.io");

        OIDCJwtAuthority authority = new OIDCJwtAuthority();
        authority.initialize();

        String token = "Bearer " + generateIdToken("https://example.com/issuer",
                System.currentTimeMillis() / 1000, "athenz", "athenz/demo", false, false);

        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate(token, "127.0.0.1", "GET", errMsg);
        assertNull(principal);
        assertTrue(errMsg.toString().contains("token issuer is not the configured issuer"));
    }

    @Test
    public void testAuthenticateAudienceMismatch() throws JOSEException {
        final String jwksUri = Objects.requireNonNull(getClass().getClassLoader().getResource("jwt_jwks.json")).toString();
        System.setProperty(OIDCJwtAuthority.ATHENZ_PROP_OIDC_JWT_JWKS_URI, jwksUri);
        System.setProperty(OIDCJwtAuthority.ATHENZ_PROP_OIDC_JWT_AUDIENCE, "https://test.athenz.io");

        OIDCJwtAuthority authority = new OIDCJwtAuthority();
        authority.initialize();

        String token = "Bearer " + generateIdToken("https://athenz-zts-server.athenz:4443/zts/v1",
                System.currentTimeMillis() / 1000, "athenz", "athenz/demo", false, false);

        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate(token, "127.0.0.1", "GET", errMsg);
        assertNull(principal);
        assertTrue(errMsg.toString().contains("token audience is not ZTS Server audience"));
    }

    @Test
    public void testAuthenticateWithoutBearerPrefix() {
        final String jwksUri = Objects.requireNonNull(getClass().getClassLoader().getResource("jwt_jwks.json")).toString();
        System.setProperty(OIDCJwtAuthority.ATHENZ_PROP_OIDC_JWT_JWKS_URI, jwksUri);

        OIDCJwtAuthority authority = new OIDCJwtAuthority();
        authority.initialize();

        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate("abc", "127.0.0.1", "GET", errMsg);
        assertNull(principal);
        assertEquals(errMsg.toString(), "OIDCJwtAuthority:authenticate: credentials do not start with Bearer");
    }

    private String generateIdToken(final String issuer, long currentTimeSecs, String enterprise,
            String repository, boolean skipIssuedAt, boolean skipRepository) throws JOSEException {

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        ECDSASigner signer = new ECDSASigner((ECPrivateKey) privateKey);
        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
                .expirationTime(Date.from(Instant.ofEpochSecond(currentTimeSecs + 3600)))
                .issuer(issuer)
                .audience("https://athenz.io")
                .subject("repo:athenz/demo:ref:refs/heads/main")
                .claim("enterprise", enterprise);
        if (!skipRepository) {
            claimsSetBuilder.claim("repository", repository);
        }
        if (!skipIssuedAt) {
            claimsSetBuilder.issueTime(Date.from(Instant.ofEpochSecond(currentTimeSecs)));
        }

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("eckey1").build(),
                claimsSetBuilder.build());
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }

    static void createOpenIdConfigFile(File configFile, File jwksUri) throws IOException {
        final String fileContents = "{\n" +
                "    \"jwks_uri\": \"file://" + jwksUri.getCanonicalPath() + "\"\n" +
                "}";
        Files.createDirectories(configFile.toPath().getParent());
        Files.write(configFile.toPath(), fileContents.getBytes());
    }

    private MockedConstruction<JwtsSigningKeyResolver> mockSigningKeyResolverConstruction() {
        return mockSigningKeyResolverConstruction(null);
    }

    private MockedConstruction<JwtsSigningKeyResolver> mockSigningKeyResolverConstruction(
            AtomicReference<String> constructedJwksUri) {
        return Mockito.mockConstruction(JwtsSigningKeyResolver.class, (mock, context) -> {
            if (constructedJwksUri != null && !context.arguments().isEmpty()) {
                constructedJwksUri.set((String) context.arguments().get(0));
            }
            Mockito.when(mock.getKeySource()).thenReturn(loadLocalJwkSourceUnchecked());
        });
    }

    private JWKSource<SecurityContext> loadLocalJwkSource() throws IOException, java.text.ParseException {
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream("jwt_jwks.json")) {
            assertNotNull(inputStream);
            return new ImmutableJWKSet<>(JWKSet.load(inputStream));
        }
    }

    private JWKSource<SecurityContext> loadLocalJwkSourceUnchecked() {
        try {
            return loadLocalJwkSource();
        } catch (IOException | java.text.ParseException ex) {
            throw new RuntimeException(ex);
        }
    }
}
