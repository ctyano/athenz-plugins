package com.yahoo.athenz.instance.provider.impl;

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
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.ProviderResourceException;
import org.apache.http.HttpEntity;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.*;

public class UserCertificateProviderTest {

    private final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");

    @BeforeMethod
    public void setup() {
        System.clearProperty(UserCertificateProvider.USER_CERT_PROP_IDP_TOKEN_ENDPOINT);
        System.clearProperty(UserCertificateProvider.USER_CERT_PROP_IDP_JWKS_ENDPOINT);
        System.clearProperty(UserCertificateProvider.USER_CERT_PROP_IDP_AUDIENCE);
        System.clearProperty(UserCertificateProvider.USER_CERT_PROP_IDP_CLIENT_ID);
    }

    @AfterMethod
    public void cleanup() {
        System.clearProperty(UserCertificateProvider.USER_CERT_PROP_IDP_TOKEN_ENDPOINT);
        System.clearProperty(UserCertificateProvider.USER_CERT_PROP_IDP_JWKS_ENDPOINT);
        System.clearProperty(UserCertificateProvider.USER_CERT_PROP_IDP_AUDIENCE);
        System.clearProperty(UserCertificateProvider.USER_CERT_PROP_IDP_CLIENT_ID);
    }

    @Test
    public void testConfirmInstanceSuccess() throws Exception {
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_IDP_TOKEN_ENDPOINT, "https://idp.com/token");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_IDP_JWKS_ENDPOINT, "https://idp.com/jwks");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_IDP_AUDIENCE, "athenz");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_IDP_CLIENT_ID, "client-id");

        String accessToken = generateToken("athenz", "john");
        String responseBody = "{\"access_token\": \"" + accessToken + "\"}";

        CloseableHttpClient mockHttpClient = Mockito.mock(CloseableHttpClient.class);
        CloseableHttpResponse mockResponse = Mockito.mock(CloseableHttpResponse.class);
        HttpEntity mockEntity = Mockito.mock(HttpEntity.class);
        StatusLine mockStatusLine = Mockito.mock(StatusLine.class);

        Mockito.when(mockStatusLine.getStatusCode()).thenReturn(200);
        Mockito.when(mockResponse.getStatusLine()).thenReturn(mockStatusLine);
        Mockito.when(mockEntity.getContent()).thenReturn(new ByteArrayInputStream(responseBody.getBytes(StandardCharsets.UTF_8)));
        Mockito.when(mockResponse.getEntity()).thenReturn(mockEntity);
        Mockito.when(mockHttpClient.execute(Mockito.any(HttpPost.class))).thenReturn(mockResponse);

        try (MockedStatic<HttpClients> mockedHttpClients = Mockito.mockStatic(HttpClients.class);
             MockedConstruction<JwtsSigningKeyResolver> mockedResolvers = mockSigningKeyResolverConstruction()) {
            
            HttpClientBuilder mockBuilder = Mockito.mock(HttpClientBuilder.class);
            mockedHttpClients.when(HttpClients::custom).thenReturn(mockBuilder);
            Mockito.when(mockBuilder.setDefaultRequestConfig(Mockito.any())).thenReturn(mockBuilder);
            Mockito.when(mockBuilder.setSSLContext(Mockito.any())).thenReturn(mockBuilder);
            Mockito.when(mockBuilder.build()).thenReturn(mockHttpClient);

            UserCertificateProvider provider = new UserCertificateProvider();
            provider.initialize("provider", "endpoint", null, null);

            InstanceConfirmation confirmation = new InstanceConfirmation();
            confirmation.setDomain("user");
            confirmation.setService("john");
            confirmation.setAttestationData("code=123&code_verifier=456");

            InstanceConfirmation result = provider.confirmInstance(confirmation);

            assertNotNull(result);
            assertEquals(result.getAttributes().get(UserCertificateProvider.ZTS_CERT_REFRESH), "false");
            assertEquals(result.getAttributes().get(UserCertificateProvider.ZTS_CERT_USAGE), "client");
        }
    }

    @Test
    public void testConfirmInstanceMissingAttestation() throws ProviderResourceException {
        UserCertificateProvider provider = new UserCertificateProvider();
        InstanceConfirmation confirmation = new InstanceConfirmation();
        
        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException e) {
            assertEquals(e.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(e.getMessage().contains("Missing attestation data"));
        }
    }

    @Test
    public void testRefreshInstanceForbidden() throws ProviderResourceException {
        UserCertificateProvider provider = new UserCertificateProvider();
        try {
            provider.refreshInstance(new InstanceConfirmation());
            fail();
        } catch (ProviderResourceException e) {
            assertEquals(e.getCode(), ProviderResourceException.FORBIDDEN);
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

    private MockedConstruction<JwtsSigningKeyResolver> mockSigningKeyResolverConstruction() {
        return Mockito.mockConstruction(JwtsSigningKeyResolver.class, (mock, context) -> {
            Mockito.when(mock.getKeySource()).thenReturn(loadLocalJwkSourceUnchecked());
        });
    }

    private JWKSource<SecurityContext> loadLocalJwkSourceUnchecked() {
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream("jwt_jwks.json")) {
            return new ImmutableJWKSet<>(JWKSet.load(inputStream));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
