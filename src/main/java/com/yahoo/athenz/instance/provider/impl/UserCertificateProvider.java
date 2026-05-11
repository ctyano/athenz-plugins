package com.yahoo.athenz.instance.provider.impl;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ProviderResourceException;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class UserCertificateProvider implements InstanceProvider {

    private static final Logger LOG = LoggerFactory.getLogger(UserCertificateProvider.class);

    public static final String USER_CERT_PROP_IDP_CONFIG_ENDPOINT = "athenz.zts.user_cert.idp_config_endpoint";
    public static final String USER_CERT_PROP_IDP_TOKEN_ENDPOINT  = "athenz.zts.user_cert.idp_token_endpoint";
    public static final String USER_CERT_PROP_IDP_JWKS_ENDPOINT   = "athenz.zts.user_cert.idp_jwks_endpoint";
    public static final String USER_CERT_PROP_IDP_CLIENT_ID       = "athenz.zts.user_cert.idp_client_id";
    public static final String USER_CERT_PROP_IDP_CLIENT_SECRET   = "athenz.zts.user_cert.idp_client_secret";
    public static final String USER_CERT_PROP_IDP_AUDIENCE        = "athenz.zts.user_cert.idp_audience";
    public static final String USER_CERT_PROP_IDP_REDIRECT_URI    = "athenz.zts.user_cert.idp_redirect_uri";
    public static final String USER_CERT_PROP_USER_NAME_CLAIM     = "athenz.zts.user_cert.user_name_claim";
    public static final String USER_CERT_PROP_CONNECT_TIMEOUT     = "athenz.zts.user_cert.connect_timeout";
    public static final String USER_CERT_PROP_READ_TIMEOUT        = "athenz.zts.user_cert.read_timeout";

    private static final String DEFAULT_REDIRECT_URI = "http://localhost:9213/oauth2/callback";
    private static final String DEFAULT_USER_NAME_CLAIM = "sub";
    private static final int DEFAULT_TIMEOUT_MS = (int) TimeUnit.MILLISECONDS.convert(5, TimeUnit.SECONDS);

    private static final int HTTP_OK = 200;

    private String idpTokenEndpoint;
    private String idpJwksEndpoint;
    private String idpClientId;
    private String idpClientSecret;
    private String idpAudience;
    private String idpRedirectUri;
    private String userNameClaim;
    private int connectTimeout;
    private int readTimeout;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private volatile ConfigurableJWTProcessor<SecurityContext> jwtProcessor;
    private CloseableHttpClient httpClient;

    @Override
    public Scheme getProviderScheme() {
        return Scheme.CLASS;
    }

    @Override
    public void initialize(final String provider, final String providerEndpoint, final SSLContext sslContext, final KeyStore keyStore) {
        final String idpConfigEndpoint = System.getProperty(USER_CERT_PROP_IDP_CONFIG_ENDPOINT);
        idpTokenEndpoint = System.getProperty(USER_CERT_PROP_IDP_TOKEN_ENDPOINT);
        idpJwksEndpoint = System.getProperty(USER_CERT_PROP_IDP_JWKS_ENDPOINT);

        idpClientId = System.getProperty(USER_CERT_PROP_IDP_CLIENT_ID);
        idpClientSecret = System.getProperty(USER_CERT_PROP_IDP_CLIENT_SECRET);
        idpAudience = System.getProperty(USER_CERT_PROP_IDP_AUDIENCE);
        idpRedirectUri = System.getProperty(USER_CERT_PROP_IDP_REDIRECT_URI, DEFAULT_REDIRECT_URI);
        userNameClaim = System.getProperty(USER_CERT_PROP_USER_NAME_CLAIM, DEFAULT_USER_NAME_CLAIM);
        
        connectTimeout = Integer.getInteger(USER_CERT_PROP_CONNECT_TIMEOUT, DEFAULT_TIMEOUT_MS);
        readTimeout = Integer.getInteger(USER_CERT_PROP_READ_TIMEOUT, DEFAULT_TIMEOUT_MS);

        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(connectTimeout)
                .setSocketTimeout(readTimeout)
                .build();
        
        httpClient = HttpClients.custom()
                .setDefaultRequestConfig(requestConfig)
                .setSSLContext(sslContext)
                .build();

        if (!StringUtil.isEmpty(idpConfigEndpoint)) {
            loadConfigFromEndpoint(idpConfigEndpoint);
        }
    }

    private void loadConfigFromEndpoint(final String configEndpoint) {
        final HttpGet httpGet;
        try {
            httpGet = new HttpGet(configEndpoint);
        } catch (IllegalArgumentException e) {
            LOG.error("Invalid OIDC configuration endpoint: {}", configEndpoint);
            return;
        }
        try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
            final int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode == HTTP_OK) {
                final HttpEntity entity = response.getEntity();
                if (entity == null) {
                    LOG.error("Failed to load OIDC configuration from {}: empty entity", configEndpoint);
                    return;
                }
                final String configJson = EntityUtils.toString(entity, StandardCharsets.UTF_8);
                final JsonNode config = objectMapper.readTree(configJson);
                if (StringUtil.isEmpty(idpTokenEndpoint) && config.has("token_endpoint")) {
                    final JsonNode node = config.get("token_endpoint");
                    if (node != null && !node.isNull()) {
                        idpTokenEndpoint = node.asText();
                    }
                }
                if (StringUtil.isEmpty(idpJwksEndpoint) && config.has("jwks_uri")) {
                    final JsonNode node = config.get("jwks_uri");
                    if (node != null && !node.isNull()) {
                        idpJwksEndpoint = node.asText();
                    }
                }
            } else {
                LOG.error("Failed to load OIDC configuration from {}: status={}", configEndpoint, statusCode);
            }
        } catch (Exception e) {
            LOG.error("Failed to load OIDC configuration from {}: {}", configEndpoint, e.getMessage());
        }
    }

    @Override
    public void setAuthorizer(final Authorizer authorizer) {
        // Not used in this implementation as we rely on IdP for identity
    }

    @Override
    public InstanceConfirmation confirmInstance(final InstanceConfirmation confirmation) throws ProviderResourceException {
        final String attestationData = confirmation.getAttestationData();
        if (StringUtil.isEmpty(attestationData)) {
            throw error("Missing attestation data", ProviderResourceException.FORBIDDEN);
        }

        final Map<String, String> params = parseQueryString(attestationData);
        final String code = params.get("code");
        final String codeVerifier = params.get("code_verifier");

        if (StringUtil.isEmpty(code)) {
            throw error("Missing authorization code", ProviderResourceException.FORBIDDEN);
        }

        // PKCE is mandatory if no client secret
        if (StringUtil.isEmpty(idpClientSecret) && StringUtil.isEmpty(codeVerifier)) {
            throw error("Missing code_verifier for PKCE", ProviderResourceException.FORBIDDEN);
        }

        final String accessToken = exchangeCodeForToken(code, codeVerifier);
        validateToken(accessToken, confirmation.getDomain(), confirmation.getService());

        // For user certificates, we don't allow refresh and we set specific usage
        final Map<String, String> attributes = new HashMap<>();
        attributes.put(ZTS_CERT_REFRESH, "false");
        attributes.put(ZTS_CERT_USAGE, ZTS_CERT_USAGE_CLIENT);
        confirmation.setAttributes(attributes);

        return confirmation;
    }

    @Override
    public InstanceConfirmation refreshInstance(final InstanceConfirmation confirmation) throws ProviderResourceException {
        throw error("User certificates cannot be refreshed", ProviderResourceException.FORBIDDEN);
    }

    private String exchangeCodeForToken(final String code, final String codeVerifier) throws ProviderResourceException {
        if (StringUtil.isEmpty(idpTokenEndpoint)) {
            throw error("IDP Token Endpoint not configured", ProviderResourceException.INTERNAL_SERVER_ERROR);
        }
        if (StringUtil.isEmpty(idpClientId)) {
            throw error("IDP Client ID not configured", ProviderResourceException.INTERNAL_SERVER_ERROR);
        }
        final HttpPost httpPost;
        try {
            httpPost = new HttpPost(idpTokenEndpoint);
        } catch (IllegalArgumentException e) {
            throw error("Invalid IDP Token Endpoint: " + idpTokenEndpoint, ProviderResourceException.INTERNAL_SERVER_ERROR);
        }
        final List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("grant_type", "authorization_code"));
        params.add(new BasicNameValuePair("code", code));
        params.add(new BasicNameValuePair("client_id", idpClientId));
        params.add(new BasicNameValuePair("redirect_uri", idpRedirectUri));
        if (!StringUtil.isEmpty(idpClientSecret)) {
            params.add(new BasicNameValuePair("client_secret", idpClientSecret));
        }
        if (!StringUtil.isEmpty(codeVerifier)) {
            params.add(new BasicNameValuePair("code_verifier", codeVerifier));
        }

        httpPost.setEntity(new UrlEncodedFormEntity(params, StandardCharsets.UTF_8));

        try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
            final int statusCode = response.getStatusLine().getStatusCode();
            final HttpEntity entity = response.getEntity();
            final String responseBody = entity != null ? EntityUtils.toString(entity, StandardCharsets.UTF_8) : "";
            if (statusCode != HTTP_OK) {
                LOG.error("Token exchange failed: status={}, body={}", statusCode, responseBody);
                throw new ProviderResourceException(ProviderResourceException.FORBIDDEN, "Token exchange failed");
            }
            final JsonNode json = objectMapper.readTree(responseBody);
            final JsonNode accessTokenNode = json != null ? json.get("access_token") : null;
            if (accessTokenNode == null || accessTokenNode.isNull() || StringUtil.isEmpty(accessTokenNode.asText())) {
                LOG.error("Token exchange response missing or invalid access_token: {}", responseBody);
                throw new ProviderResourceException(ProviderResourceException.FORBIDDEN, "Token exchange failed: missing access_token");
            }
            return accessTokenNode.asText();
        } catch (IOException e) {
            LOG.error("Token exchange failed due to network error: {}", e.getMessage());
            throw new ProviderResourceException(ProviderResourceException.FORBIDDEN, "Token exchange failed: " + e.getMessage());
        }
    }

    private void validateToken(String token, String domain, String service) throws ProviderResourceException {
        ConfigurableJWTProcessor<SecurityContext> processor = getJwtProcessor();
        if (processor == null) {
            throw error("JWT Processor not initialized", ProviderResourceException.INTERNAL_SERVER_ERROR);
        }

        try {
            JWTClaimsSet claimsSet = processor.process(token, null);
            
            // Validate Audience
            if (StringUtil.isEmpty(idpAudience)) {
                throw error("IDP Audience not configured", ProviderResourceException.INTERNAL_SERVER_ERROR);
            }
            if (!Objects.equals(idpAudience, JwtsHelper.getAudience(claimsSet))) {
                throw error("Invalid token audience", ProviderResourceException.FORBIDDEN);
            }

            // Validate Subject (User Name)
            String principalName = JwtsHelper.getStringClaim(claimsSet, userNameClaim);
            if (StringUtil.isEmpty(principalName)) {
                throw error("Token missing user name claim: " + userNameClaim, ProviderResourceException.FORBIDDEN);
            }

            // The user name in Athenz can be "user.<name>" or just "<name>" depending on context.
            // ZTS expected domain.service for the principal.
            String expectedPrincipal = domain + "." + service;
            if (!principalName.equalsIgnoreCase(service) && !principalName.equalsIgnoreCase(expectedPrincipal)) {
                throw error("Token subject mismatch: " + principalName + " vs " + expectedPrincipal, ProviderResourceException.FORBIDDEN);
            }

        } catch (Exception e) {
            throw error("Token validation failed: " + e.getMessage(), ProviderResourceException.FORBIDDEN);
        }
    }

    private ConfigurableJWTProcessor<SecurityContext> getJwtProcessor() {
        if (jwtProcessor != null) {
            return jwtProcessor;
        }
        synchronized (this) {
            if (jwtProcessor != null) {
                return jwtProcessor;
            }
            if (StringUtil.isEmpty(idpJwksEndpoint)) {
                return null;
            }
            jwtProcessor = JwtsHelper.getJWTProcessor(new JwtsSigningKeyResolver(idpJwksEndpoint, null));
            return jwtProcessor;
        }
    }

    private Map<String, String> parseQueryString(String query) {
        Map<String, String> params = new HashMap<>();
        if (StringUtil.isEmpty(query)) {
            return params;
        }
        for (String pair : query.split("&")) {
            int idx = pair.indexOf("=");
            if (idx > 0) {
                String key = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8);
                String value = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8);
                params.put(key, value);
            }
        }
        return params;
    }

    @Override
    public void close() {
        if (httpClient != null) {
            try {
                httpClient.close();
            } catch (IOException e) {
                LOG.error("Failed to close HTTP client: {}", e.getMessage());
            }
        }
    }

    private ProviderResourceException error(String message, int code) {
        LOG.error(message);
        return new ProviderResourceException(code, message);
    }
}
