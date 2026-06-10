package com.yahoo.athenz.instance.provider.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ProviderResourceException;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

public class InstanceLocalWorkloadProviderTest {

    private static final String ISSUER = "https://idp.example.test";
    private static final String ISSUER_EXTERNAL = "https://external-idp.example.test";
    private static final String AUDIENCE = "athenz-local-workload";

    private final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");
    private final ClassLoader classLoader = this.getClass().getClassLoader();

    @AfterMethod
    public void clearProperties() {
        System.clearProperty(InstanceLocalWorkloadProvider.LOCAL_WORKLOAD_PROP_ISSUER);
        System.clearProperty(InstanceLocalWorkloadProvider.LOCAL_WORKLOAD_PROP_JWKS_URI);
        System.clearProperty(InstanceLocalWorkloadProvider.LOCAL_WORKLOAD_PROP_JWKS_URI_MAP);
        System.clearProperty(InstanceLocalWorkloadProvider.LOCAL_WORKLOAD_PROP_AUDIENCE);
        System.clearProperty(InstanceLocalWorkloadProvider.LOCAL_WORKLOAD_PROP_USER_NAME_CLAIM);
        System.clearProperty(InstanceLocalWorkloadProvider.LOCAL_WORKLOAD_PROP_USER_DOMAIN_TEMPLATE);
        System.clearProperty(InstanceLocalWorkloadProvider.LOCAL_WORKLOAD_PROP_EXTERNAL_DOMAIN);
        System.clearProperty(InstanceLocalWorkloadProvider.LOCAL_WORKLOAD_PROP_EXTERNAL_DOMAIN_MAP);
        System.clearProperty(InstanceLocalWorkloadProvider.LOCAL_WORKLOAD_PROP_BOOT_TIME_OFFSET);
    }

    @Test
    public void testConfirmInstanceWithUserHomeDomain() throws Exception {
        configureSingleIssuer();
        System.setProperty(InstanceLocalWorkloadProvider.LOCAL_WORKLOAD_PROP_USER_DOMAIN_TEMPLATE,
                "home.%s.local.workloads");

        InstanceLocalWorkloadProvider provider = newProvider();
        assertEquals(provider.getProviderScheme(), InstanceProvider.Scheme.CLASS);

        InstanceConfirmation confirmation = newConfirmation("home.alice.local.workloads.dev", "api",
                "Bearer " + generateToken(ISSUER, AUDIENCE, "user.Alice"));

        InstanceConfirmation result = provider.confirmInstance(confirmation);

        assertNotNull(result);
        assertEquals(result.getAttributes().get(InstanceProvider.ZTS_CERT_REFRESH), "false");
        assertEquals(result.getAttributes().get(InstanceProvider.ZTS_CERT_USAGE), "client");
    }

    @Test
    public void testConfirmInstanceWithUserHomeDomainRejectsOtherUserDomain() throws Exception {
        configureSingleIssuer();

        InstanceLocalWorkloadProvider provider = newProvider();
        InstanceConfirmation confirmation = newConfirmation("home.bob", "api",
                generateToken(ISSUER, AUDIENCE, "alice"));

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("outside the allowed domain"));
        }
    }

    @Test
    public void testConfirmInstanceWithExternalIssuerDomain() throws Exception {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceLocalWorkloadProvider.LOCAL_WORKLOAD_PROP_AUDIENCE, AUDIENCE);
        System.setProperty(InstanceLocalWorkloadProvider.LOCAL_WORKLOAD_PROP_JWKS_URI_MAP,
                ISSUER_EXTERNAL + "=" + jwksUri);
        System.setProperty(InstanceLocalWorkloadProvider.LOCAL_WORKLOAD_PROP_EXTERNAL_DOMAIN_MAP,
                ISSUER_EXTERNAL + "=external.dex.workloads");

        InstanceLocalWorkloadProvider provider = newProvider();
        InstanceConfirmation confirmation = newConfirmation("external.dex.workloads.team1", "api",
                generateToken(ISSUER_EXTERNAL, AUDIENCE, null));

        InstanceConfirmation result = provider.confirmInstance(confirmation);

        assertNotNull(result);
        assertEquals(result.getAttributes().get(InstanceProvider.ZTS_CERT_REFRESH), "false");
    }

    @Test
    public void testConfirmInstanceWithExternalIssuerRejectsWrongDomain() throws Exception {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceLocalWorkloadProvider.LOCAL_WORKLOAD_PROP_AUDIENCE, AUDIENCE);
        System.setProperty(InstanceLocalWorkloadProvider.LOCAL_WORKLOAD_PROP_JWKS_URI_MAP,
                ISSUER_EXTERNAL + "=" + jwksUri);
        System.setProperty(InstanceLocalWorkloadProvider.LOCAL_WORKLOAD_PROP_EXTERNAL_DOMAIN_MAP,
                ISSUER_EXTERNAL + "=external.okta");

        InstanceLocalWorkloadProvider provider = newProvider();
        InstanceConfirmation confirmation = newConfirmation("home.alice", "api",
                generateToken(ISSUER_EXTERNAL, AUDIENCE, null));

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("outside the allowed domain"));
        }
    }

    @Test
    public void testConfirmInstanceWithInvalidAudience() throws Exception {
        configureSingleIssuer();

        InstanceLocalWorkloadProvider provider = newProvider();
        InstanceConfirmation confirmation = newConfirmation("home.alice", "api",
                generateToken(ISSUER, "other-audience", "alice"));

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Token audience is not configured"));
        }
    }

    @Test
    public void testConfirmInstanceWithoutAttestationData() {
        configureSingleIssuer();

        InstanceLocalWorkloadProvider provider = newProvider();
        InstanceConfirmation confirmation = newConfirmation("home.alice", "api", null);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Service credentials not provided"));
        }
    }

    @Test
    public void testRefreshInstanceForbidden() {
        InstanceLocalWorkloadProvider provider = new InstanceLocalWorkloadProvider();

        try {
            provider.refreshInstance(new InstanceConfirmation());
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("cannot be refreshed"));
        }
    }

    private void configureSingleIssuer() {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceLocalWorkloadProvider.LOCAL_WORKLOAD_PROP_ISSUER, ISSUER);
        System.setProperty(InstanceLocalWorkloadProvider.LOCAL_WORKLOAD_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceLocalWorkloadProvider.LOCAL_WORKLOAD_PROP_AUDIENCE, AUDIENCE);
    }

    private InstanceLocalWorkloadProvider newProvider() {
        InstanceLocalWorkloadProvider provider = new InstanceLocalWorkloadProvider();
        provider.initialize("sys.auth.local-workload",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceLocalWorkloadProvider", null, null);
        return provider;
    }

    private InstanceConfirmation newConfirmation(final String domain, final String service,
            final String attestationData) {
        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setProvider("sys.auth.local-workload");
        confirmation.setDomain(domain);
        confirmation.setService(service);
        confirmation.setAttestationData(attestationData);
        return confirmation;
    }

    private String generateToken(final String issuer, final String audience, final String userName)
            throws JOSEException {
        final long currentTimeSecs = System.currentTimeMillis() / 1000;
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        ECDSASigner signer = new ECDSASigner((ECPrivateKey) privateKey);
        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(audience)
                .subject("user-token")
                .issueTime(Date.from(Instant.ofEpochSecond(currentTimeSecs)))
                .expirationTime(Date.from(Instant.ofEpochSecond(currentTimeSecs + 3600)));
        if (userName != null) {
            claimsSetBuilder.claim(InstanceLocalWorkloadProvider.DEFAULT_USER_NAME_CLAIM, userName);
        }

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("eckey1").build(),
                claimsSetBuilder.build());
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }
}
