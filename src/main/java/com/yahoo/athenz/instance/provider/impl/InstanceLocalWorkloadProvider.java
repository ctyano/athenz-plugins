package com.yahoo.athenz.instance.provider.impl;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ProviderResourceException;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.text.ParseException;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

public class InstanceLocalWorkloadProvider implements InstanceProvider {

    private static final Logger LOG = LoggerFactory.getLogger(InstanceLocalWorkloadProvider.class);

    public static final String LOCAL_WORKLOAD_PROP_ISSUER =
            "athenz.zts.local_workload.issuer";
    public static final String LOCAL_WORKLOAD_PROP_JWKS_URI =
            "athenz.zts.local_workload.jwks_uri";
    public static final String LOCAL_WORKLOAD_PROP_JWKS_URI_MAP =
            "athenz.zts.local_workload.jwks_uri_map";
    public static final String LOCAL_WORKLOAD_PROP_AUDIENCE =
            "athenz.zts.local_workload.audience";
    public static final String LOCAL_WORKLOAD_PROP_USER_NAME_CLAIM =
            "athenz.zts.local_workload.user_name_claim";
    public static final String LOCAL_WORKLOAD_PROP_USER_DOMAIN_TEMPLATE =
            "athenz.zts.local_workload.user_domain_template";
    public static final String LOCAL_WORKLOAD_PROP_EXTERNAL_DOMAIN =
            "athenz.zts.local_workload.external_domain";
    public static final String LOCAL_WORKLOAD_PROP_EXTERNAL_DOMAIN_MAP =
            "athenz.zts.local_workload.external_domain_map";
    public static final String LOCAL_WORKLOAD_PROP_BOOT_TIME_OFFSET =
            "athenz.zts.local_workload.boot_time_offset";

    static final String DEFAULT_USER_NAME_CLAIM = "name";
    static final String DEFAULT_USER_DOMAIN_TEMPLATE = "home.%s";
    static final long DEFAULT_BOOT_TIME_OFFSET_SECONDS = 0;
    static final String BEARER_PREFIX = "Bearer ";

    String provider = null;
    SSLContext sslContext = null;
    Set<String> audiences = Collections.emptySet();
    String userNameClaim = DEFAULT_USER_NAME_CLAIM;
    String userDomainTemplate = DEFAULT_USER_DOMAIN_TEMPLATE;
    long bootTimeOffsetSeconds = DEFAULT_BOOT_TIME_OFFSET_SECONDS;
    final JwtsHelper jwtsHelper = new JwtsHelper();
    final ConcurrentMap<String, IssuerConfig> issuerConfigs = new ConcurrentHashMap<>();

    @Override
    public Scheme getProviderScheme() {
        return Scheme.CLASS;
    }

    @Override
    public void initialize(final String provider, final String providerEndpoint, final SSLContext sslContext,
            final KeyStore keyStore) {
        this.provider = provider;
        this.sslContext = sslContext;
        issuerConfigs.clear();

        audiences = parseCsvSet(System.getProperty(LOCAL_WORKLOAD_PROP_AUDIENCE));
        userNameClaim = System.getProperty(LOCAL_WORKLOAD_PROP_USER_NAME_CLAIM, DEFAULT_USER_NAME_CLAIM);
        userDomainTemplate = System.getProperty(LOCAL_WORKLOAD_PROP_USER_DOMAIN_TEMPLATE, DEFAULT_USER_DOMAIN_TEMPLATE);
        bootTimeOffsetSeconds = parseLong(System.getProperty(LOCAL_WORKLOAD_PROP_BOOT_TIME_OFFSET),
                DEFAULT_BOOT_TIME_OFFSET_SECONDS);

        final Map<String, String> jwksUriMap = parseMap(System.getProperty(LOCAL_WORKLOAD_PROP_JWKS_URI_MAP));
        final Map<String, String> externalDomainMap = parseMap(System.getProperty(LOCAL_WORKLOAD_PROP_EXTERNAL_DOMAIN_MAP));

        final Set<String> configuredIssuers = parseCsvSet(System.getProperty(LOCAL_WORKLOAD_PROP_ISSUER));
        for (String issuer : configuredIssuers) {
            issuerConfigs.put(issuer, new IssuerConfig(issuer, jwksUriMap.get(issuer),
                    System.getProperty(LOCAL_WORKLOAD_PROP_EXTERNAL_DOMAIN)));
        }

        for (Map.Entry<String, String> entry : externalDomainMap.entrySet()) {
            issuerConfigs.compute(entry.getKey(), (issuer, existingConfig) -> new IssuerConfig(issuer,
                    existingConfig == null ? jwksUriMap.get(issuer) : existingConfig.jwksUri, entry.getValue()));
        }

        for (Map.Entry<String, String> entry : jwksUriMap.entrySet()) {
            issuerConfigs.compute(entry.getKey(), (issuer, existingConfig) -> new IssuerConfig(issuer,
                    entry.getValue(), existingConfig == null ? null : existingConfig.externalDomain));
        }

        final String jwksUri = System.getProperty(LOCAL_WORKLOAD_PROP_JWKS_URI);
        final String externalDomain = System.getProperty(LOCAL_WORKLOAD_PROP_EXTERNAL_DOMAIN);
        if (configuredIssuers.size() == 1 && !StringUtil.isEmpty(jwksUri) && !jwksUri.trim().isEmpty()) {
            final String issuer = configuredIssuers.iterator().next();
            issuerConfigs.put(issuer, new IssuerConfig(issuer, jwksUri.trim(), externalDomain));
        }
    }

    @Override
    public InstanceConfirmation confirmInstance(final InstanceConfirmation confirmation) throws ProviderResourceException {
        if (confirmation == null) {
            throw error("Instance confirmation request not provided", ProviderResourceException.BAD_REQUEST);
        }

        final String domain = confirmation.getDomain();
        final String service = confirmation.getService();
        if (StringUtil.isEmpty(domain) || StringUtil.isEmpty(service)) {
            throw error("Domain and service must be provided", ProviderResourceException.BAD_REQUEST);
        }

        final String attestationData = normalizeAttestationData(confirmation.getAttestationData());
        if (StringUtil.isEmpty(attestationData)) {
            throw error("Service credentials not provided", ProviderResourceException.FORBIDDEN);
        }

        final JWTClaimsSet claimsSet = validateToken(attestationData);
        final String allowedRootDomain = resolveAllowedRootDomain(claimsSet);
        if (StringUtil.isEmpty(allowedRootDomain)) {
            throw error("Unable to resolve allowed domain for token issuer", ProviderResourceException.FORBIDDEN);
        }

        if (!isDomainInScope(domain, allowedRootDomain)) {
            throw error("Requested service is outside the allowed domain", ProviderResourceException.FORBIDDEN);
        }

        final Map<String, String> attributes = new HashMap<>();
        attributes.put(ZTS_CERT_REFRESH, "false");
        attributes.put(ZTS_CERT_USAGE, ZTS_CERT_USAGE_CLIENT);
        confirmation.setAttributes(attributes);
        return confirmation;
    }

    @Override
    public InstanceConfirmation refreshInstance(final InstanceConfirmation confirmation) throws ProviderResourceException {
        throw error("Local workload certificates cannot be refreshed", ProviderResourceException.FORBIDDEN);
    }

    JWTClaimsSet validateToken(final String token) throws ProviderResourceException {
        final String tokenIssuer = extractIssuer(token);
        final IssuerConfig issuerConfig = issuerConfigs.get(tokenIssuer);
        if (issuerConfig == null) {
            throw error("Token issuer is not configured: " + tokenIssuer, ProviderResourceException.FORBIDDEN);
        }

        final ConfigurableJWTProcessor<SecurityContext> processor = getJwtProcessor(issuerConfig);
        if (processor == null) {
            throw error("JWT Processor not initialized", ProviderResourceException.INTERNAL_SERVER_ERROR);
        }

        final JWTClaimsSet claimsSet;
        try {
            claimsSet = processor.process(token, null);
        } catch (Exception ex) {
            throw error("Unable to parse and validate token: " + ex.getMessage(), ProviderResourceException.FORBIDDEN);
        }

        if (!issuerConfig.issuer.equals(claimsSet.getIssuer())) {
            throw error("Token issuer does not match configured issuer: " + claimsSet.getIssuer(),
                    ProviderResourceException.FORBIDDEN);
        }

        validateAudience(claimsSet);
        validateExpiration(claimsSet);
        validateIssueTime(claimsSet);
        return claimsSet;
    }

    String extractIssuer(final String token) throws ProviderResourceException {
        try {
            final SignedJWT signedJWT = SignedJWT.parse(token);
            final String issuer = signedJWT.getJWTClaimsSet().getIssuer();
            if (StringUtil.isEmpty(issuer)) {
                throw error("Token does not contain required iss claim", ProviderResourceException.FORBIDDEN);
            }
            return issuer;
        } catch (ParseException ex) {
            throw error("Unable to parse token: " + ex.getMessage(), ProviderResourceException.FORBIDDEN);
        }
    }

    ConfigurableJWTProcessor<SecurityContext> getJwtProcessor(final IssuerConfig issuerConfig) {
        ConfigurableJWTProcessor<SecurityContext> processor = issuerConfig.jwtProcessor;
        if (processor != null) {
            return processor;
        }
        synchronized (issuerConfig) {
            processor = issuerConfig.jwtProcessor;
            if (processor != null) {
                return processor;
            }

            String jwksUri = issuerConfig.jwksUri;
            if (StringUtil.isEmpty(jwksUri)) {
                jwksUri = extractIssuerJwksUri(issuerConfig.issuer);
            }
            if (StringUtil.isEmpty(jwksUri)) {
                jwksUri = issuerConfig.issuer + "/.well-known/jwks";
            }

            issuerConfig.jwtProcessor = JwtsHelper.getJWTProcessor(new JwtsSigningKeyResolver(jwksUri, sslContext));
            return issuerConfig.jwtProcessor;
        }
    }

    String extractIssuerJwksUri(final String issuer) {
        if (StringUtil.isEmpty(issuer)) {
            return null;
        }
        return jwtsHelper.extractJwksUri(issuer + "/.well-known/openid-configuration", sslContext);
    }

    void validateAudience(final JWTClaimsSet claimsSet) throws ProviderResourceException {
        if (audiences == null || audiences.isEmpty()) {
            throw error("Local workload audience not configured", ProviderResourceException.INTERNAL_SERVER_ERROR);
        }

        final List<String> audienceList = claimsSet.getAudience();
        final Set<String> tokenAudiences = audienceList == null ? Collections.emptySet() : new HashSet<>(audienceList);
        if (tokenAudiences.stream().noneMatch(audiences::contains)) {
            throw error("Token audience is not configured local workload audience: " + tokenAudiences,
                    ProviderResourceException.FORBIDDEN);
        }
    }

    void validateExpiration(final JWTClaimsSet claimsSet) throws ProviderResourceException {
        if (claimsSet.getExpirationTime() == null) {
            throw error("Token does not contain required exp claim", ProviderResourceException.FORBIDDEN);
        }
    }

    void validateIssueTime(final JWTClaimsSet claimsSet) throws ProviderResourceException {
        if (bootTimeOffsetSeconds <= 0) {
            return;
        }
        final Date issueTime = claimsSet.getIssueTime();
        if (issueTime == null || issueTime.getTime() < System.currentTimeMillis() -
                TimeUnit.SECONDS.toMillis(bootTimeOffsetSeconds)) {
            throw error("Token issue time is not recent enough, issued at: " + issueTime,
                    ProviderResourceException.FORBIDDEN);
        }
    }

    String resolveAllowedRootDomain(final JWTClaimsSet claimsSet) throws ProviderResourceException {
        final String userName = normalizeUserName(JwtsHelper.getStringClaim(claimsSet, userNameClaim));
        if (!StringUtil.isEmpty(userName)) {
            return buildUserRootDomain(userName);
        }

        final IssuerConfig issuerConfig = issuerConfigs.get(claimsSet.getIssuer());
        return issuerConfig == null ? null : normalizeDomain(issuerConfig.externalDomain);
    }

    String buildUserRootDomain(final String userName) throws ProviderResourceException {
        if (StringUtil.isEmpty(userDomainTemplate)) {
            throw error("User domain template not configured", ProviderResourceException.INTERNAL_SERVER_ERROR);
        }
        if (!userDomainTemplate.contains("%s")) {
            throw error("User domain template must contain %s", ProviderResourceException.INTERNAL_SERVER_ERROR);
        }
        final String normalizedUserName = normalizeUserName(userName);
        if (StringUtil.isEmpty(normalizedUserName)) {
            return null;
        }
        return normalizeDomain(userDomainTemplate.replace("%s", normalizedUserName));
    }

    boolean isDomainInScope(final String domain, final String rootDomain) {
        final String normalizedDomain = normalizeDomain(domain);
        final String normalizedRootDomain = normalizeDomain(rootDomain);
        if (StringUtil.isEmpty(normalizedDomain) || StringUtil.isEmpty(normalizedRootDomain)) {
            return false;
        }
        return normalizedDomain.equals(normalizedRootDomain) ||
                normalizedDomain.startsWith(normalizedRootDomain + ".");
    }

    String normalizeAttestationData(final String attestationData) {
        if (attestationData == null) {
            return null;
        }
        final String trimmed = attestationData.trim();
        return trimmed.startsWith(BEARER_PREFIX) ? trimmed.substring(BEARER_PREFIX.length()).trim() : trimmed;
    }

    String normalizeUserName(final String userName) {
        if (StringUtil.isEmpty(userName)) {
            return null;
        }
        String normalizedUserName = userName.trim().toLowerCase(Locale.ROOT);
        if (normalizedUserName.startsWith("user.")) {
            normalizedUserName = normalizedUserName.substring("user.".length());
        }
        return normalizedUserName.isEmpty() ? null : normalizedUserName;
    }

    String normalizeDomain(final String domain) {
        if (StringUtil.isEmpty(domain)) {
            return null;
        }
        final String normalizedDomain = domain.trim().toLowerCase(Locale.ROOT);
        return normalizedDomain.isEmpty() ? null : normalizedDomain;
    }

    Set<String> parseCsvSet(final String propertyValue) {
        if (StringUtil.isEmpty(propertyValue)) {
            return Collections.emptySet();
        }
        final Set<String> values = new HashSet<>();
        for (String value : propertyValue.split(",")) {
            final String trimmed = value.trim();
            if (!trimmed.isEmpty()) {
                values.add(trimmed);
            }
        }
        return values;
    }

    Map<String, String> parseMap(final String propertyValue) {
        if (StringUtil.isEmpty(propertyValue)) {
            return Collections.emptyMap();
        }
        final Map<String, String> values = new HashMap<>();
        for (String entry : propertyValue.split(";")) {
            final int separatorIdx = entry.indexOf('=');
            if (separatorIdx <= 0 || separatorIdx == entry.length() - 1) {
                LOG.warn("Ignoring invalid local workload map entry: {}", entry);
                continue;
            }
            final String key = entry.substring(0, separatorIdx).trim();
            final String value = entry.substring(separatorIdx + 1).trim();
            if (!key.isEmpty() && !value.isEmpty()) {
                values.put(key, value);
            }
        }
        return values;
    }

    long parseLong(final String propertyValue, final long defaultValue) {
        if (StringUtil.isEmpty(propertyValue)) {
            return defaultValue;
        }
        try {
            return Long.parseLong(propertyValue);
        } catch (NumberFormatException ex) {
            LOG.warn("Invalid local workload long property value: {}, using default: {}", propertyValue, defaultValue);
            return defaultValue;
        }
    }

    private ProviderResourceException error(final String message, final int code) {
        LOG.error(message);
        return new ProviderResourceException(code, message);
    }

    static final class IssuerConfig {

        final String issuer;
        final String jwksUri;
        final String externalDomain;
        volatile ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

        IssuerConfig(final String issuer, final String jwksUri, final String externalDomain) {
            this.issuer = Objects.requireNonNull(issuer);
            this.jwksUri = jwksUri;
            this.externalDomain = externalDomain;
        }
    }
}
