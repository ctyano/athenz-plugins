package com.yahoo.athenz.common.server.cert.impl.vault;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.common.server.ServerResourceException;
import org.testng.annotations.Test;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import static org.testng.Assert.*;

public class VaultCertSignerTest {

    private static final String TEST_CSR = "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----";
    private static final String TEST_CERT = "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----";
    private static final String TEST_TOKEN = "s.test-token-value";

    private String buildVaultCertResponse(String certificate) {
        try {
            java.util.Map<String, Object> data = new java.util.LinkedHashMap<>();
            data.put("certificate", certificate);
            java.util.Map<String, Object> response = new java.util.LinkedHashMap<>();
            response.put("data", data);
            return new ObjectMapper().writeValueAsString(response);
        } catch (Exception e) {
            return null;
        }
    }

    private String buildVaultCaResponse(String caCert, String[] caChain) {
        try {
            java.util.Map<String, Object> data = new java.util.LinkedHashMap<>();
            if (caCert != null) {
                data.put("certificate", caCert);
            }
            if (caChain != null) {
                data.put("ca_chain", caChain);
            }
            java.util.Map<String, Object> response = new java.util.LinkedHashMap<>();
            response.put("data", data);
            return new ObjectMapper().writeValueAsString(response);
        } catch (Exception e) {
            return null;
        }
    }

    static class StubHttpResponse implements HttpResponse<String> {
        final int statusCode;
        final String body;
        StubHttpResponse(int statusCode, String body) {
            this.statusCode = statusCode;
            this.body = body;
        }
        public int statusCode() { return statusCode; }
        public String body() { return body; }
        public HttpHeaders headers() { return HttpHeaders.of(java.util.Map.of(), (a, b) -> true); }
        public Optional<HttpResponse<String>> previousResponse() { return Optional.empty(); }
        public Optional<javax.net.ssl.SSLSession> sslSession() { return Optional.empty(); }
        public HttpRequest request() { return null; }
        public URI uri() { return null; }
        public HttpClient.Version version() { return HttpClient.Version.HTTP_2; }
        public Optional<HttpClient.Redirect> followRedirects() { return Optional.empty(); }
    }

    // --- generateX509Certificate tests ---

    @Test
    public void testGenerateX509CertificateSuccess() throws Exception {
        String vaultResponse = buildVaultCertResponse(TEST_CERT);

        VaultCertSigner signer = new VaultCertSigner(null, "https://vault.example.com:8200",
                "pki", "athenz", "role-id", "secret-id", "approle", 43200) {
            @Override
            String getVaultToken() {
                return TEST_TOKEN;
            }
            @Override
            String sendHttpRequest(String uri, String jsonBody) throws IOException {
                return vaultResponse;
            }
        };

        String cert = signer.generateX509Certificate("provider", null, TEST_CSR,
                null, 360, null, null);
        assertEquals(cert, TEST_CERT);
    }

    @Test
    public void testGenerateX509CertificateEmptyCsr() throws ServerResourceException {
        VaultCertSigner signer = new VaultCertSigner(null, "https://vault.example.com:8200",
                "pki", "athenz", "role-id", "secret-id", "approle", 43200);

        String result = signer.generateX509Certificate("provider", null, "",
                null, 360, null, null);
        assertNull(result);
    }

    @Test
    public void testGenerateX509CertificateSendHttpReturnsNull() throws Exception {
        VaultCertSigner signer = new VaultCertSigner(null, "https://vault.example.com:8200",
                "pki", "athenz", "role-id", "secret-id", "approle", 43200) {
            @Override
            String getVaultToken() {
                return TEST_TOKEN;
            }
            @Override
            String sendHttpRequest(String uri, String jsonBody) throws IOException {
                return null;
            }
        };

        String result = signer.generateX509Certificate("provider", null, TEST_CSR,
                null, 360, null, null);
        assertNull(result);
    }

    @Test
    public void testGenerateX509CertificateIOException() throws Exception {
        VaultCertSigner signer = new VaultCertSigner(null, "https://vault.example.com:8200",
                "pki", "athenz", "role-id", "secret-id", "approle", 43200) {
            @Override
            String getVaultToken() {
                return TEST_TOKEN;
            }
            @Override
            String sendHttpRequest(String uri, String jsonBody) throws IOException {
                throw new IOException("connection failed");
            }
        };

        String result = signer.generateX509Certificate("provider", null, TEST_CSR,
                null, 360, null, null);
        assertNull(result);
    }

    @Test
    public void testGenerateX509CertificateWithTtl() throws Exception {
        String vaultResponse = buildVaultCertResponse(TEST_CERT);

        VaultCertSigner signer = new VaultCertSigner(null, "https://vault.example.com:8200",
                "pki", "athenz", "role-id", "secret-id", "approle", 43200) {
            @Override
            String getVaultToken() {
                return TEST_TOKEN;
            }
            @Override
            String sendHttpRequest(String uri, String jsonBody) throws IOException {
                assertTrue(jsonBody.contains("\"ttl\":\"60m\""));
                return vaultResponse;
            }
        };

        String cert = signer.generateX509Certificate("provider", null, TEST_CSR,
                null, 60, null, null);
        assertEquals(cert, TEST_CERT);
    }

    @Test
    public void testGenerateX509CertificateExpiryExceedsMax() throws Exception {
        String vaultResponse = buildVaultCertResponse(TEST_CERT);

        VaultCertSigner signer = new VaultCertSigner(null, "https://vault.example.com:8200",
                "pki", "athenz", "role-id", "secret-id", "approle", 30) {
            @Override
            String getVaultToken() {
                return TEST_TOKEN;
            }
            @Override
            String sendHttpRequest(String uri, String jsonBody) throws IOException {
                assertFalse(jsonBody.contains("\"ttl\""));
                return vaultResponse;
            }
        };

        String cert = signer.generateX509Certificate("provider", null, TEST_CSR,
                null, 60, null, null);
        assertNotNull(cert);
    }

    // --- sendHttpRequest 401 retry tests ---

    @Test
    public void testSendHttpRequestRetriesOn401() throws Exception {
        String vaultResponse = buildVaultCertResponse(TEST_CERT);

        VaultCertSigner signer = new VaultCertSigner(null, "https://vault.example.com:8200",
                "pki", "athenz", "role-id", "secret-id", "approle", 43200) {
            private int callCount = 0;
            @Override
            String getVaultToken() {
                return TEST_TOKEN;
            }
            @Override
            HttpResponse<String> doPost(String uri, String jsonBody, String token) {
                if (callCount++ == 0) {
                    return new StubHttpResponse(401, "");
                }
                return new StubHttpResponse(200, vaultResponse);
            }
        };

        String cert = signer.generateX509Certificate("provider", null, TEST_CSR,
                null, 360, null, null);
        assertEquals(cert, TEST_CERT);
    }

    @Test
    public void testSendHttpRequestRetryExhaustedOnRepeated401() throws Exception {
        VaultCertSigner signer = new VaultCertSigner(null, "https://vault.example.com:8200",
                "pki", "athenz", "role-id", "secret-id", "approle", 43200) {
            @Override
            String getVaultToken() {
                return TEST_TOKEN;
            }
            @Override
            HttpResponse<String> doPost(String uri, String jsonBody, String token) {
                return new StubHttpResponse(401, "");
            }
        };

        String result = signer.generateX509Certificate("provider", null, TEST_CSR,
                null, 360, null, null);
        assertNull(result);
    }

    // --- extractCertificate tests ---

    @Test
    public void testExtractCertificateSuccess() {
        String vaultResponse = buildVaultCertResponse(TEST_CERT);
        VaultCertSigner signer = new VaultCertSigner(null, "https://vault.example.com:8200",
                "pki", "athenz", "role-id", "secret-id", "approle", 43200);

        String result = signer.extractCertificate(vaultResponse);
        assertEquals(result, TEST_CERT);
    }

    @Test
    public void testExtractCertificateNoData() {
        VaultCertSigner signer = new VaultCertSigner(null, "https://vault.example.com:8200",
                "pki", "athenz", "role-id", "secret-id", "approle", 43200);
        assertNull(signer.extractCertificate("{}"));
    }

    @Test
    public void testExtractCertificateNoCertificate() {
        VaultCertSigner signer = new VaultCertSigner(null, "https://vault.example.com:8200",
                "pki", "athenz", "role-id", "secret-id", "approle", 43200);
        assertNull(signer.extractCertificate("{\"data\":{}}"));
    }

    @Test
    public void testExtractCertificateInvalidJson() {
        VaultCertSigner signer = new VaultCertSigner(null, "https://vault.example.com:8200",
                "pki", "athenz", "role-id", "secret-id", "approle", 43200);
        assertNull(signer.extractCertificate("invalid json"));
    }

    // --- getCACertificate tests ---

    @Test
    public void testGetCACertificateWithChain() throws Exception {
        String ca1 = "-----BEGIN CERTIFICATE-----\nCA1\n-----END CERTIFICATE-----";
        String ca2 = "-----BEGIN CERTIFICATE-----\nCA2\n-----END CERTIFICATE-----";
        String vaultResponse = buildVaultCaResponse(null, new String[]{ca1, ca2});

        VaultCertSigner signer = new VaultCertSigner(null, "https://vault.example.com:8200",
                "pki", "athenz", "role-id", "secret-id", "approle", 43200) {
            @Override
            String getVaultToken() {
                return TEST_TOKEN;
            }
            @Override
            String sendHttpGetRequest(String uri) throws IOException {
                return vaultResponse;
            }
        };

        assertEquals(signer.getCACertificate("provider", null), ca1 + ca2);
    }

    @Test
    public void testGetCACertificateWithSingleCert() throws Exception {
        String vaultResponse = buildVaultCaResponse(TEST_CERT, null);

        VaultCertSigner signer = new VaultCertSigner(null, "https://vault.example.com:8200",
                "pki", "athenz", "role-id", "secret-id", "approle", 43200) {
            @Override
            String getVaultToken() {
                return TEST_TOKEN;
            }
            @Override
            String sendHttpGetRequest(String uri) throws IOException {
                return vaultResponse;
            }
        };

        assertEquals(signer.getCACertificate("provider", null), TEST_CERT);
    }

    @Test
    public void testGetCACertificateSendGetReturnsNull() throws Exception {
        VaultCertSigner signer = new VaultCertSigner(null, "https://vault.example.com:8200",
                "pki", "athenz", "role-id", "secret-id", "approle", 43200) {
            @Override
            String getVaultToken() {
                return TEST_TOKEN;
            }
            @Override
            String sendHttpGetRequest(String uri) throws IOException {
                return null;
            }
        };

        assertNull(signer.getCACertificate("provider", null));
    }

    @Test
    public void testGetCACertificateIOException() throws Exception {
        VaultCertSigner signer = new VaultCertSigner(null, "https://vault.example.com:8200",
                "pki", "athenz", "role-id", "secret-id", "approle", 43200) {
            @Override
            String getVaultToken() {
                return TEST_TOKEN;
            }
            @Override
            String sendHttpGetRequest(String uri) throws IOException {
                throw new IOException("connection failed");
            }
        };

        assertNull(signer.getCACertificate("provider", null));
    }

    // --- getMaxCertExpiryTimeMins ---

    @Test
    public void testGetMaxCertExpiryTimeMins() {
        VaultCertSigner signer = new VaultCertSigner(null, "https://vault.example.com:8200",
                "pki", "athenz", "role-id", "secret-id", "approle", 43200);
        assertEquals(signer.getMaxCertExpiryTimeMins(), 43200);
    }

    // --- close ---

    @Test
    public void testClose() {
        VaultCertSigner signer = new VaultCertSigner(null, "https://vault.example.com:8200",
                "pki", "athenz", "role-id", "secret-id", "approle", 43200);
        signer.close();
    }

    // --- authenticate tests ---

    @Test
    public void testAuthenticateSuccess() {
        VaultCertSigner signer = new VaultCertSigner(null, "https://vault.example.com:8200",
                "pki", "athenz", "role-id", "secret-id", "approle", 43200) {
            @Override
            String authenticate() {
                return TEST_TOKEN;
            }
        };
        assertEquals(signer.authenticate(), TEST_TOKEN);
    }

    @Test
    public void testAuthenticateReturnsNull() {
        VaultCertSigner signer = new VaultCertSigner(null, "https://vault.example.com:8200",
                "pki", "athenz", "role-id", "secret-id", "approle", 43200) {
            @Override
            String authenticate() {
                return null;
            }
        };
        assertNull(signer.authenticate());
    }

    // --- getVaultToken tests ---

    @Test
    public void testGetVaultTokenCachesToken() {
        final int[] callCount = {0};
        VaultCertSigner signer = new VaultCertSigner(null, "https://vault.example.com:8200",
                "pki", "athenz", "role-id", "secret-id", "approle", 43200) {
            @Override
            String authenticate() {
                callCount[0]++;
                return TEST_TOKEN;
            }
        };

        assertEquals(signer.getVaultToken(), TEST_TOKEN);
        assertEquals(signer.getVaultToken(), TEST_TOKEN);
        assertEquals(callCount[0], 1);
    }

    @Test
    public void testGetVaultTokenReturnsNullWhenAuthFails() {
        VaultCertSigner signer = new VaultCertSigner(null, "https://vault.example.com:8200",
                "pki", "athenz", "role-id", "secret-id", "approle", 43200) {
            @Override
            String authenticate() {
                return null;
            }
        };
        assertNull(signer.getVaultToken());
    }

    // --- constructor tests ---

    @Test
    public void testConstructorWithSystemProperties() {
        System.setProperty("athenz.zts.vault.base_uri", "https://vault.example.com:8200");
        System.setProperty("athenz.zts.vault.approle_role_id", "test-role-id");
        System.setProperty("athenz.zts.vault.approle_secret_id", "test-secret-id");
        System.setProperty("athenz.zts.vault.pki_path", "custom-pki");
        System.setProperty("athenz.zts.vault.role_name", "custom-role");
        System.setProperty("athenz.zts.vault.approle_mount_path", "custom-approle");
        System.setProperty("athenz.zts.certsign_max_expiry_time", "1440");

        VaultCertSigner signer = new VaultCertSigner();
        assertNotNull(signer);
        assertEquals(signer.getMaxCertExpiryTimeMins(), 1440);

        System.clearProperty("athenz.zts.vault.base_uri");
        System.clearProperty("athenz.zts.vault.approle_role_id");
        System.clearProperty("athenz.zts.vault.approle_secret_id");
        System.clearProperty("athenz.zts.vault.pki_path");
        System.clearProperty("athenz.zts.vault.role_name");
        System.clearProperty("athenz.zts.vault.approle_mount_path");
        System.clearProperty("athenz.zts.certsign_max_expiry_time");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testConstructorMissingBaseUri() {
        System.clearProperty("athenz.zts.vault.base_uri");
        System.setProperty("athenz.zts.vault.approle_role_id", "test-role-id");
        System.setProperty("athenz.zts.vault.approle_secret_id", "test-secret-id");
        try {
            new VaultCertSigner();
        } finally {
            System.clearProperty("athenz.zts.vault.approle_role_id");
            System.clearProperty("athenz.zts.vault.approle_secret_id");
        }
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testConstructorMissingRoleId() {
        System.setProperty("athenz.zts.vault.base_uri", "https://vault.example.com:8200");
        System.clearProperty("athenz.zts.vault.approle_role_id");
        System.setProperty("athenz.zts.vault.approle_secret_id", "test-secret-id");
        try {
            new VaultCertSigner();
        } finally {
            System.clearProperty("athenz.zts.vault.base_uri");
            System.clearProperty("athenz.zts.vault.approle_secret_id");
        }
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testConstructorMissingSecretId() {
        System.setProperty("athenz.zts.vault.base_uri", "https://vault.example.com:8200");
        System.setProperty("athenz.zts.vault.approle_role_id", "test-role-id");
        System.clearProperty("athenz.zts.vault.approle_secret_id");
        try {
            new VaultCertSigner();
        } finally {
            System.clearProperty("athenz.zts.vault.base_uri");
            System.clearProperty("athenz.zts.vault.approle_role_id");
        }
    }
}
