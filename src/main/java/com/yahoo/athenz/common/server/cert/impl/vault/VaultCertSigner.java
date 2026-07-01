package com.yahoo.athenz.common.server.cert.impl.vault;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.cert.CertSigner;
import com.yahoo.athenz.common.server.cert.Priority;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

public class VaultCertSigner implements CertSigner {

    private static final Logger LOGGER = LoggerFactory.getLogger(VaultCertSigner.class);

    private static final String CONTENT_JSON = "application/json";
    private static final String VAULT_TOKEN_HEADER = "X-Vault-Token";

    protected static final ObjectMapper JACKSON_MAPPER = new ObjectMapper();

    private final HttpClient httpClient;
    private final String baseUri;
    private final String pkiPath;
    private final String roleName;
    private final String roleId;
    private final String secretId;
    private final String approleMountPath;
    private final int maxCertExpiryTimeMins;

    private volatile String vaultToken;

    public VaultCertSigner() {

        baseUri = System.getProperty("athenz.zts.vault.base_uri");
        if (StringUtil.isEmpty(baseUri)) {
            LOGGER.error("VaultCertSigner: no base uri specified");
            throw new IllegalArgumentException("No Vault base uri specified: athenz.zts.vault.base_uri");
        }

        pkiPath = System.getProperty("athenz.zts.vault.pki_path", "pki");
        roleName = System.getProperty("athenz.zts.vault.role_name", "athenz");

        roleId = System.getProperty("athenz.zts.vault.approle_role_id");
        if (StringUtil.isEmpty(roleId)) {
            LOGGER.error("VaultCertSigner: no approle role id specified");
            throw new IllegalArgumentException("No Vault AppRole role id specified: athenz.zts.vault.approle_role_id");
        }

        secretId = System.getProperty("athenz.zts.vault.approle_secret_id");
        if (StringUtil.isEmpty(secretId)) {
            LOGGER.error("VaultCertSigner: no approle secret id specified");
            throw new IllegalArgumentException("No Vault AppRole secret id specified: athenz.zts.vault.approle_secret_id");
        }

        approleMountPath = System.getProperty("athenz.zts.vault.approle_mount_path", "approle");

        int connectTimeout = Integer.parseInt(System.getProperty("athenz.zts.vault.connect_timeout", "10"));
        maxCertExpiryTimeMins = Integer.parseInt(
                System.getProperty("athenz.zts.certsign_max_expiry_time", "43200"));

        httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(connectTimeout))
                .build();

        LOGGER.info("VaultCertSigner initialized with baseUri: {}", baseUri);
    }

    VaultCertSigner(HttpClient httpClient, String baseUri, String pkiPath, String roleName,
                    String roleId, String secretId, String approleMountPath,
                    int maxCertExpiryTimeMins) {
        this.httpClient = httpClient;
        this.baseUri = baseUri;
        this.pkiPath = pkiPath;
        this.roleName = roleName;
        this.roleId = roleId;
        this.secretId = secretId;
        this.approleMountPath = approleMountPath;
        this.maxCertExpiryTimeMins = maxCertExpiryTimeMins;
    }

    @Override
    public String generateX509Certificate(String provider, String certIssuer, String csr,
                                          String keyUsage, int expiryTime, Priority priority,
                                          String signerKeyId) throws ServerResourceException {
        if (StringUtil.isEmpty(csr)) {
            LOGGER.error("VaultCertSigner: empty CSR provided");
            return null;
        }

        String signUri = baseUri + "/v1/" + pkiPath + "/sign/" + roleName;

        Map<String, Object> requestBody = new LinkedHashMap<>();
        requestBody.put("csr", csr);
        int ttl = expiryTime;
        if (ttl > maxCertExpiryTimeMins) {
            ttl = maxCertExpiryTimeMins;
        }
        if (ttl > 0) {
            requestBody.put("ttl", ttl + "m");
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("VaultCertSigner: signing certificate at uri: {}", signUri);
        }

        try {
            String jsonBody = JACKSON_MAPPER.writeValueAsString(requestBody);
            String responseBody = sendHttpRequest(signUri, jsonBody);
            if (responseBody == null) {
                return null;
            }
            return extractCertificate(responseBody);
        } catch (IOException e) {
            LOGGER.error("VaultCertSigner: IO error while signing certificate", e);
            return null;
        }
    }

    String sendHttpRequest(String uri, String jsonBody) throws IOException {
        String token = getVaultToken();
        if (token == null) {
            return null;
        }
        HttpResponse<String> response = doPost(uri, jsonBody, token);

        if (response == null) {
            return null;
        }

        if (response.statusCode() == 401) {
            LOGGER.info("VaultCertSigner: token expired, re-authenticating");
            synchronized (this) {
                if (token.equals(vaultToken)) {
                    vaultToken = null;
                }
            }
            token = getVaultToken();
            if (token == null) {
                return null;
            }
            response = doPost(uri, jsonBody, token);
        }

        if (response.statusCode() != 200) {
            LOGGER.error("VaultCertSigner: request failed, status: {}, body: {}",
                    response.statusCode(), response.body());
            return null;
        }
        return response.body();
    }

    String sendHttpGetRequest(String uri) throws IOException {
        String token = getVaultToken();
        if (token == null) {
            return null;
        }
        HttpResponse<String> response = doGet(uri, token);

        if (response == null) {
            return null;
        }

        if (response.statusCode() == 401) {
            LOGGER.info("VaultCertSigner: token expired, re-authenticating");
            synchronized (this) {
                if (token.equals(vaultToken)) {
                    vaultToken = null;
                }
            }
            token = getVaultToken();
            if (token == null) {
                return null;
            }
            response = doGet(uri, token);
        }

        if (response.statusCode() != 200) {
            LOGGER.error("VaultCertSigner: request failed, status: {}, body: {}",
                    response.statusCode(), response.body());
            return null;
        }
        return response.body();
    }

    HttpResponse<String> doPost(String uri, String jsonBody, String token) throws IOException {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(uri))
                    .header("Content-Type", CONTENT_JSON)
                    .header("Accept", CONTENT_JSON)
                    .header(VAULT_TOKEN_HEADER, token)
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .build();
            return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            LOGGER.error("VaultCertSigner: request interrupted", e);
            Thread.currentThread().interrupt();
            return null;
        }
    }

    HttpResponse<String> doGet(String uri, String token) throws IOException {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(uri))
                    .header("Accept", CONTENT_JSON)
                    .header(VAULT_TOKEN_HEADER, token)
                    .GET()
                    .build();
            return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            LOGGER.error("VaultCertSigner: request interrupted", e);
            Thread.currentThread().interrupt();
            return null;
        }
    }

    String getVaultToken() {
        if (vaultToken != null) {
            return vaultToken;
        }
        synchronized (this) {
            if (vaultToken != null) {
                return vaultToken;
            }
            vaultToken = authenticate();
            return vaultToken;
        }
    }

    String authenticate() {
        String loginUri = baseUri + "/v1/auth/" + approleMountPath + "/login";

        Map<String, String> loginBody = new LinkedHashMap<>();
        loginBody.put("role_id", roleId);
        loginBody.put("secret_id", secretId);

        try {
            String jsonBody = JACKSON_MAPPER.writeValueAsString(loginBody);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(loginUri))
                    .header("Content-Type", CONTENT_JSON)
                    .header("Accept", CONTENT_JSON)
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                LOGGER.error("VaultCertSigner: AppRole login failed, status: {}, body: {}",
                        response.statusCode(), response.body());
                return null;
            }

            Map<?, ?> responseMap = JACKSON_MAPPER.readValue(response.body(), Map.class);
            Map<?, ?> auth = (Map<?, ?>) responseMap.get("auth");
            if (auth == null) {
                LOGGER.error("VaultCertSigner: no auth block in AppRole login response");
                return null;
            }
            Object tokenObj = auth.get("client_token");
            if (tokenObj == null) {
                LOGGER.error("VaultCertSigner: no client_token in AppRole login response");
                return null;
            }

            String token = tokenObj.toString();
            LOGGER.info("VaultCertSigner: successfully authenticated via AppRole");
            return token;
        } catch (IOException e) {
            LOGGER.error("VaultCertSigner: IO error during AppRole authentication", e);
            return null;
        } catch (InterruptedException e) {
            LOGGER.error("VaultCertSigner: authentication interrupted", e);
            Thread.currentThread().interrupt();
            return null;
        }
    }

    String extractCertificate(String responseBody) {
        try {
            Map<?, ?> responseMap = JACKSON_MAPPER.readValue(responseBody, Map.class);
            Map<?, ?> data = (Map<?, ?>) responseMap.get("data");
            if (data == null) {
                LOGGER.error("VaultCertSigner: no data in response");
                return null;
            }
            Object certObj = data.get("certificate");
            if (certObj == null) {
                LOGGER.error("VaultCertSigner: no certificate in response data");
                return null;
            }
            return certObj.toString();
        } catch (Exception e) {
            LOGGER.error("VaultCertSigner: failed to parse certificate response", e);
            return null;
        }
    }

    @Override
    public String getCACertificate(String provider, String signerKeyId) {
        String caUri = baseUri + "/v1/" + pkiPath + "/ca_chain";

        try {
            String responseBody = sendHttpGetRequest(caUri);
            if (responseBody == null) {
                return null;
            }

            Map<?, ?> responseMap = JACKSON_MAPPER.readValue(responseBody, Map.class);
            Map<?, ?> data = (Map<?, ?>) responseMap.get("data");
            if (data == null) {
                LOGGER.error("VaultCertSigner: no data in CA response");
                return null;
            }

            Object caChain = data.get("ca_chain");
            if (caChain instanceof Iterable) {
                StringBuilder sb = new StringBuilder(4096);
                for (Object cert : (Iterable<?>) caChain) {
                    if (cert != null) {
                        String certStr = cert.toString();
                        sb.append(certStr);
                        if (!certStr.endsWith("\n")) {
                            sb.append("\n");
                        }
                    }
                }
                return sb.toString();
            }

            Object certificate = data.get("certificate");
            if (certificate != null) {
                return certificate.toString();
            }

            LOGGER.error("VaultCertSigner: no ca_chain or certificate in CA response data");
            return null;
        } catch (IOException e) {
            LOGGER.error("VaultCertSigner: IO error while getting CA certificate", e);
            return null;
        }
    }

    @Override
    public int getMaxCertExpiryTimeMins() {
        return maxCertExpiryTimeMins;
    }

    @Override
    public void close() {}
}
