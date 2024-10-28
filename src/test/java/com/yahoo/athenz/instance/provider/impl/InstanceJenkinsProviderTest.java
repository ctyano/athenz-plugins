package com.yahoo.athenz.instance.provider.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ProviderResourceException;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.HashMap;
import java.util.Objects;

import static org.testng.Assert.*;

public class InstanceJenkinsProviderTest {

    private final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");

    private final ClassLoader classLoader = this.getClass().getClassLoader();

    @AfterMethod
    public void tearDown() {
        System.clearProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI);
        System.clearProperty(InstanceJenkinsProvider.JENKINS_PROP_AUDIENCE);
        System.clearProperty(InstanceJenkinsProvider.JENKINS_PROP_ISSUER);
    }

    static void createOpenIdConfigFile(File configFile, File jwksUri) throws IOException {

        String fileContents;
        if (jwksUri == null) {
            fileContents = "{}";
        } else {
            fileContents = "{\n" +
                    "    \"jwks_uri\": \"file://" + jwksUri.getCanonicalPath() + "\"\n" +
                    "}";
        }
        Files.createDirectories(configFile.toPath().getParent());
        Files.write(configFile.toPath(), fileContents.getBytes());
    }

    @Test
    public void testInitializeWithConfig() {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI, jwksUri);

        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);
        assertEquals(provider.getProviderScheme(), InstanceProvider.Scheme.CLASS);
    }

    @Test
    public void testInitializeWithOpenIdConfig() throws IOException {

        File issuerFile = new File("./src/test/resources/config-openid/");
        File configFile = new File("./src/test/resources/config-openid/.well-known/openid-configuration");
        File jwksUriFile = new File("./src/test/resources/jwt-jwks.json");
        createOpenIdConfigFile(configFile, jwksUriFile);

        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_ISSUER, "file://" + issuerFile.getCanonicalPath());

        // std test where the http driver will return null for the config object

        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);
        assertNotNull(provider);
        Files.delete(configFile.toPath());
    }

    @Test
    public void testInitializeWithOpenIdConfigMissingUri() throws IOException {

        File issuerFile = new File("./src/test/resources/config-openid/");
        File configFile = new File("./src/test/resources/config-openid/.well-known/openid-configuration");
        createOpenIdConfigFile(configFile, null);

        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_ISSUER, "file://" + issuerFile.getCanonicalPath());

        // std test where the http driver will return null for the config object

        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);
        assertNotNull(provider);
        Files.delete(configFile.toPath());
    }

    @Test
    public void testConfirmInstance() throws JOSEException, ProviderResourceException {

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_AUDIENCE, "https://athenz.io");

        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal principal = SimplePrincipal.create("sports", "api", (String) null);
        Mockito.when(authorizer.access("jenkins-pipeline", "sports:https://jenkins.athenz.svc.cluster.local/job/test-project/1", principal, null))
                .thenReturn(true);
        provider.setAuthorizer(authorizer);

        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_ID, "jenkins.athenz.svc.cluster.local:job:test-project:1");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "spiffe://ns/default/sports/api,athenz://instanceid/sys.auth.jenkins/athenz:sia:001");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.jenkins.athenz.io");

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.jenkins");
        confirmation.setAttestationData(generateIdToken("https://jenkins.athenz.svc.cluster.local/oidc",
                System.currentTimeMillis() / 1000, false, false));
        confirmation.setAttributes(instanceAttributes);

        InstanceConfirmation confirmResponse = provider.confirmInstance(confirmation);
        assertNotNull(confirmResponse);
        assertEquals(confirmResponse.getAttributes().get(InstanceProvider.ZTS_CERT_REFRESH), "false");
        assertEquals(confirmResponse.getAttributes().get(InstanceProvider.ZTS_CERT_USAGE), "client");
        assertEquals(confirmResponse.getAttributes().get(InstanceProvider.ZTS_CERT_EXPIRY_TIME), "360");
    }

    @Test
    public void testConfirmInstanceFailuresInvalidSANEntries() throws JOSEException {

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_AUDIENCE, "https://athenz.io");

        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal principal = SimplePrincipal.create("sports", "api", (String) null);
        Mockito.when(authorizer.access("jenkins-pipeline", "sports:https://jenkins.athenz.svc.cluster.local/job/test-project/1", principal, null))
                .thenReturn(true);
        provider.setAuthorizer(authorizer);

        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_ID, "jenkins.athenz.svc.cluster.local:job:test-project:1");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "spiffe://ns/default/sports/api,athenz://instanceid/sys.auth.jenkins/athenz:sia:001");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "host1.athenz.io");

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.jenkins");
        confirmation.setAttestationData(generateIdToken("https://jenkins.athenz.svc.cluster.local/oidc",
                System.currentTimeMillis() / 1000, false, false));
        confirmation.setAttributes(instanceAttributes);

        // we should get a failure due to invalid san dns entry

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Unable to validate certificate request sanDNS entries"));
        }
    }

    @Test
    public void testConfirmInstanceFailuresNoPublicKey() throws JOSEException {

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks_empty.json")).toString();
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_AUDIENCE, "https://athenz.io");

        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal principal = SimplePrincipal.create("sports", "api", (String) null);
        Mockito.when(authorizer.access("jenkins-pipeline", "sports:https://jenkins.athenz.svc.cluster.local/job/test-project/1", principal, null))
                .thenReturn(true);
        provider.setAuthorizer(authorizer);

        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_ID, "jenkins.athenz.svc.cluster.local:job:test-project:1");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "spiffe://ns/default/sports/api,athenz://instanceid/sys.auth.jenkins/athenz:sia:001");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "host1.athenz.io");

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.jenkins");
        confirmation.setAttestationData(generateIdToken("https://jenkins.athenz.svc.cluster.local/oidc",
                System.currentTimeMillis() / 1000, false, false));
        confirmation.setAttributes(instanceAttributes);

        // without the public key we should get a token validation failure

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Signed JWT rejected: Another algorithm expected, or no matching key(s) found"));
        }
    }

    @Test
    public void testConfirmInstanceWithoutAuthorizer() {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI, jwksUri);
        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);
        provider.setAuthorizer(null);
        try {
            provider.confirmInstance(null);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Authorizer not available"));
        }
    }

    @Test
    public void testConfirmInstanceWithSanIP() {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI, jwksUri);
        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_IP, "10.1.1.1");
        confirmation.setAttributes(instanceAttributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Request must not have any sanIP addresses"));
        }
    }

    @Test
    public void testConfirmInstanceWithHostname() {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI, jwksUri);
        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_HOSTNAME, "host1.athenz.io");
        confirmation.setAttributes(instanceAttributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Request must not have any hostname values"));
        }
    }

    @Test
    public void testConfirmInstanceWithSanURI() {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI, jwksUri);
        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "spiffe://ns/athenz.production/instanceid,https://athenz.io");
        confirmation.setAttributes(instanceAttributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Unable to validate certificate request URI values"));
        }
    }

    @Test
    public void testConfirmInstanceWithoutAttestationData() {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI, jwksUri);
        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Service credentials not provided"));
        }
    }

    @Test
    public void testRefreshNotSupported() {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI, jwksUri);
        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);
        try {
            provider.refreshInstance(null);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("GitHub Action X.509 Certificates cannot be refreshed"));
        }
    }

    @Test
    public void testValidateSanUri() {
        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        assertTrue(provider.validateSanUri(null));
        assertTrue(provider.validateSanUri(""));
        assertTrue(provider.validateSanUri("spiffe://ns/athenz.production/instanceid"));
        assertTrue(provider.validateSanUri("athenz://instanceid/athenz.production/instanceid"));
        assertTrue(provider.validateSanUri("athenz://instanceid/athenz.production/instanceid,spiffe://ns/athenz.production/instanceid"));
        assertFalse(provider.validateSanUri("athenz://instanceid/athenz.production/instanceid,spiffe://ns/athenz.production/instanceid,https://athenz.io"));
        assertFalse(provider.validateSanUri("athenz://hostname/host1,athenz://instanceid/athenz.production/instanceid"));
        assertFalse(provider.validateSanUri("athenz://hostname/host1"));
    }

    @Test
    public void testValidateOIDCTokenWithoutJWTProcessor() {

        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();

        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(provider.validateOIDCToken("some-jwt", "sports", "api", "jenkins.athenz.svc.cluster.local:job:test-project:1", errMsg));
        assertTrue(errMsg.toString().contains("JWT Processor not initialized"));

        provider.close();
    }

    @Test
    public void testValidateOIDCTokenIssuerMismatch() throws JOSEException {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_AUDIENCE, "https://athenz.io");

        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);

        // our issuer will not match

        String idToken = generateIdToken("https://token.actions.githubusercontent.com",
                System.currentTimeMillis() / 1000, false, false);
        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(idToken, "sports", "api", "jenkins.athenz.svc.cluster.local:job:test-project:1", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token issuer is not Jenkins"));
    }

    @Test
    public void testValidateOIDCTokenAudienceMismatch() throws JOSEException {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_AUDIENCE, "https://test.athenz.io");

        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);

        // our audience will not match

        String idToken = generateIdToken("https://jenkins.athenz.svc.cluster.local/oidc",
                System.currentTimeMillis() / 1000, false, false);
        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(idToken, "sports", "api", "jenkins.athenz.svc.cluster.local:job:test-project:1", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token audience is not ZTS Server audience"));
    }

    @Test
    public void testValidateOIDCTokenStartNotRecentEnough() throws JOSEException {

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_AUDIENCE, "https://athenz.io");

        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);

        // our issue time is not recent enough

        String idToken = generateIdToken("https://jenkins.athenz.svc.cluster.local/oidc",
                System.currentTimeMillis() / 1000 - 400, false, false);
        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(idToken, "sports", "api", "jenkins.athenz.svc.cluster.local:job:test-project:1", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("job start time is not recent enough"));

        // create another token without the issue time

        idToken = generateIdToken("https://jenkins.athenz.svc.cluster.local/oidc",
                System.currentTimeMillis() / 1000, false, true);
        errMsg.setLength(0);
        result = provider.validateOIDCToken(idToken, "sports", "api", "jenkins.athenz.svc.cluster.local:job:test-project:1", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("job start time is not recent enough"));
    }

    @Test
    public void testValidateOIDCTokenMissingSubject() throws JOSEException {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_AUDIENCE, "https://athenz.io");

        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);

        // create an id token without the subject claim

        String idToken = generateIdToken("https://jenkins.athenz.svc.cluster.local/oidc",
                System.currentTimeMillis() / 1000, true, false);

        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(idToken, "sports", "api", "jenkins.athenz.svc.cluster.local:job:test-project:1", errMsg);
        assertFalse(result);
        assertEquals(errMsg.toString(),"token does not contain required subject claim");
        assertTrue(errMsg.toString().contains("token does not contain required subject claim"));
    }

    @Test
    public void testValidateOIDCTokenAuthorizationFailure() throws JOSEException {

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_AUDIENCE, "https://athenz.io");

        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal principal = SimplePrincipal.create("sports", "api", (String) null);
        Mockito.when(authorizer.access("jenkins-pipeline", "sports:https://jenkins.athenz.svc.cluster.local/job/test-project/1", principal, null))
                .thenReturn(false);
        provider.setAuthorizer(authorizer);

        // create an id token

        String idToken = generateIdToken("https://jenkins.athenz.svc.cluster.local/oidc",
                System.currentTimeMillis() / 1000, false, false);

        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(idToken, "sports", "api", "jenkins.athenz.svc.cluster.local:job:test-project:1", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("authorization check failed for action"));
    }

    private String generateIdToken(final String issuer, long currentTimeSecs, boolean skipSubject,
            boolean skipIssuedAt) throws JOSEException {

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        JWSSigner signer = new ECDSASigner((ECPrivateKey) privateKey);
        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
                .expirationTime(Date.from(Instant.ofEpochSecond(currentTimeSecs + 3600)))
                .issuer(issuer)
                .audience("https://athenz.io")
                .claim("enterprise", "athenz");
        if (!skipSubject) {
            claimsSetBuilder.subject("https://jenkins.athenz.svc.cluster.local/job/test-project/1");
        }
        if (!skipIssuedAt) {
            claimsSetBuilder.issueTime(Date.from(Instant.ofEpochSecond(currentTimeSecs)));
        }

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("eckey1").build(),
                claimsSetBuilder.build());
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }
}