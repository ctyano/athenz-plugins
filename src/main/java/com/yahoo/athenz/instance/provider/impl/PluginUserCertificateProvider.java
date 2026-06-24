package com.yahoo.athenz.instance.provider.impl;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.yahoo.athenz.auth.AuthorityConsts;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ProviderResourceException;
import org.apache.http.HttpEntity;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class PluginUserCertificateProvider implements InstanceProvider {

    private static final Logger LOG = LoggerFactory.getLogger(PluginUserCertificateProvider.class);

    public static final String USER_CERT_PROP_IDP_CONFIG_ENDPOINT = "athenz.zts.user_cert.idp_config_endpoint";
    public static final String USER_CERT_PROP_IDP_JWKS_ENDPOINT   = "athenz.zts.user_cert.idp_jwks_endpoint";
    public static final String USER_CERT_PROP_IDP_AUDIENCE        = "athenz.zts.user_cert.idp_audience";
    public static final String USER_CERT_PROP_USER_NAME_CLAIM     = "athenz.zts.user_cert.user_name_claim";
    public static final String USER_CERT_PROP_CONNECT_TIMEOUT     = "athenz.zts.user_cert.connect_timeout";
    public static final String USER_CERT_PROP_READ_TIMEOUT        = "athenz.zts.user_cert.read_timeout";

    private static final String DEFAULT_USER_NAME_CLAIM = "sub";
    private static final String EXTERNAL_SERVICE_PREFIX = "ext.";
    private static final int DEFAULT_TIMEOUT_MS = (int) TimeUnit.MILLISECONDS.convert(5, TimeUnit.SECONDS);

    private static final int HTTP_OK = 200;

    private String idpJwksEndpoint;
    private String idpAudience;
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
        idpJwksEndpoint = System.getProperty(USER_CERT_PROP_IDP_JWKS_ENDPOINT);

        idpAudience = System.getProperty(USER_CERT_PROP_IDP_AUDIENCE);
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

        validateToken(attestationData, confirmation.getDomain(), confirmation.getService());

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

            final List<String> expectedPrincipals = expectedPrincipalNames(domain, service);
            if (!matchesPrincipal(principalName, expectedPrincipals)) {
                throw error("Token subject mismatch: " + principalName + " vs " + expectedPrincipals, ProviderResourceException.FORBIDDEN);
            }

        } catch (ProviderResourceException e) {
            throw e;
        } catch (Exception e) {
            throw error("Token validation failed: " + e.getMessage(), ProviderResourceException.FORBIDDEN);
        }
    }

    private boolean matchesPrincipal(final String principalName, final List<String> expectedPrincipals) {
        for (String expectedPrincipal : expectedPrincipals) {
            if (principalName.equalsIgnoreCase(expectedPrincipal)) {
                return true;
            }
        }
        return false;
    }

    private List<String> expectedPrincipalNames(final String domain, final String service) {
        final List<String> expectedPrincipals = new ArrayList<>();
        addExpectedPrincipal(expectedPrincipals, service);

        if (StringUtil.isEmpty(domain) || StringUtil.isEmpty(service)) {
            return expectedPrincipals;
        }

        final String externalLocalName = externalLocalName(domain, service);
        if (!StringUtil.isEmpty(externalLocalName)) {
            addExpectedPrincipal(expectedPrincipals, externalLocalName);
            addExpectedPrincipal(expectedPrincipals, domain + AuthorityConsts.EXT_SEP + externalLocalName);
        } else {
            addExpectedPrincipal(expectedPrincipals, domain + AuthorityConsts.ATHENZ_PRINCIPAL_DELIMITER + service);
        }
        return expectedPrincipals;
    }

    private String externalLocalName(final String domain, final String service) {
        final int idx = service.indexOf(AuthorityConsts.EXT_SEP);
        if (idx != -1) {
            final String externalDomain = service.substring(0, idx);
            if (domain.equalsIgnoreCase(externalDomain)) {
                return service.substring(idx + AuthorityConsts.EXT_SEP.length());
            }
            return null;
        }

        if (service.regionMatches(true, 0, EXTERNAL_SERVICE_PREFIX, 0, EXTERNAL_SERVICE_PREFIX.length())) {
            return service.substring(EXTERNAL_SERVICE_PREFIX.length());
        }
        return null;
    }

    private void addExpectedPrincipal(final List<String> expectedPrincipals, final String principalName) {
        if (StringUtil.isEmpty(principalName)) {
            return;
        }
        for (String expectedPrincipal : expectedPrincipals) {
            if (expectedPrincipal.equalsIgnoreCase(principalName)) {
                return;
            }
        }
        expectedPrincipals.add(principalName);
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
