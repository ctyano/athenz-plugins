package com.yahoo.athenz.instance.provider.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.ProviderResourceException;
import org.testng.annotations.Test;

import java.io.File;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.util.Date;

import static org.testng.Assert.*;

public class PluginUserCertificateProviderTest {

    private final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");

    @Test
    public void testConfirmInstanceSuccess() throws Exception {
        String accessToken = generateToken("athenz", "john");

        PluginUserCertificateProvider provider = new PluginUserCertificateProvider();
        setField(provider, "idpAudience", "athenz");
        setField(provider, "userNameClaim", "sub");
        setField(provider, "jwtProcessor", buildLocalJwtProcessor());

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("user");
        confirmation.setService("john");
        confirmation.setAttestationData(accessToken);

        InstanceConfirmation result = provider.confirmInstance(confirmation);

        assertNotNull(result);
        assertEquals(result.getAttributes().get(PluginUserCertificateProvider.ZTS_CERT_REFRESH), "false");
        assertEquals(result.getAttributes().get(PluginUserCertificateProvider.ZTS_CERT_USAGE), "client");
        provider.close();
    }

    @Test
    public void testConfirmInstanceMissingAttestation() throws ProviderResourceException {
        PluginUserCertificateProvider provider = new PluginUserCertificateProvider();
        InstanceConfirmation confirmation = new InstanceConfirmation();

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException e) {
            assertEquals(e.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(e.getMessage().contains("Missing attestation data"));
        } finally {
            provider.close();
        }
    }

    @Test
    public void testRefreshInstanceForbidden() throws ProviderResourceException {
        PluginUserCertificateProvider provider = new PluginUserCertificateProvider();
        try {
            provider.refreshInstance(new InstanceConfirmation());
            fail();
        } catch (ProviderResourceException e) {
            assertEquals(e.getCode(), ProviderResourceException.FORBIDDEN);
        } finally {
            provider.close();
        }
    }

    private String generateToken(String audience, String subject) throws JOSEException {
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        ECDSASigner signer = new ECDSASigner((ECPrivateKey) privateKey);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .expirationTime(new Date(System.currentTimeMillis() + 3600 * 1000))
                .audience(audience)
                .subject(subject)
                .issueTime(new Date())
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("eckey1").build(),
                claimsSet);
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }

    private ConfigurableJWTProcessor<SecurityContext> buildLocalJwtProcessor() {
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(JWSAlgorithm.ES256, loadLocalJwkSourceUnchecked());
        processor.setJWSKeySelector(keySelector);
        return processor;
    }

    private JWKSource<SecurityContext> loadLocalJwkSourceUnchecked() {
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream("jwt_jwks.json")) {
            return new ImmutableJWKSet<>(JWKSet.load(inputStream));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void setField(Object target, String fieldName, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }
}
