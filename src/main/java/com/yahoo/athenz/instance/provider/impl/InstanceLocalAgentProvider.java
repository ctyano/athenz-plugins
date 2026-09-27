package com.yahoo.athenz.instance.provider.impl;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.TokenExchangeIdentityProvider;
import com.yahoo.athenz.auth.token.OAuth2Token;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.common.server.db.RolesProvider;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ProviderResourceException;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMember;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.text.ParseException;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

public class InstanceLocalAgentProvider implements InstanceProvider {

    private static final Logger LOG = LoggerFactory.getLogger(InstanceLocalAgentProvider.class);

    public static final String LOCAL_AGENT_PROP_ISSUER =
            "athenz.zts.local_agent.issuer";
    public static final String LOCAL_AGENT_PROP_JWKS_URI =
            "athenz.zts.local_agent.jwks_uri";
    public static final String LOCAL_AGENT_PROP_JWKS_URI_MAP =
            "athenz.zts.local_agent.jwks_uri_map";
    public static final String LOCAL_AGENT_PROP_AUDIENCE =
            "athenz.zts.local_agent.audience";
    public static final String LOCAL_AGENT_PROP_USER_NAME_CLAIM =
            "athenz.zts.local_agent.user_name_claim";
    public static final String LOCAL_AGENT_PROP_USER_NAME_CLAIMS =
            "athenz.zts.local_agent.user_name_claims";
    public static final String LOCAL_AGENT_PROP_USER_DOMAIN_TEMPLATE =
            "athenz.zts.local_agent.user_domain_template";
    public static final String LOCAL_AGENT_PROP_EXTERNAL_MEMBER_CLAIMS =
            "athenz.zts.local_agent.external_member_claims";
    public static final String LOCAL_AGENT_PROP_EXTERNAL_MEMBER_TEMPLATE =
            "athenz.zts.local_agent.external_member_template";
    public static final String LOCAL_AGENT_PROP_EXTERNAL_IDENTITY_PROVIDER_CLASS =
            "athenz.zts.local_agent.external_identity_provider_class";
    public static final String LOCAL_AGENT_PROP_BOOT_TIME_OFFSET =
            "athenz.zts.local_agent.boot_time_offset";

    static final String DEFAULT_USER_NAME_CLAIMS = "athenz_user,preferred_username,name,sub";
    static final String DEFAULT_EXTERNAL_MEMBER_CLAIMS = "external_members,email,preferred_username,sub";
    static final String DEFAULT_EXTERNAL_MEMBER_TEMPLATE = "%s";
    static final String DEFAULT_USER_DOMAIN_TEMPLATE = "home.%s";
    static final long DEFAULT_BOOT_TIME_OFFSET_SECONDS = 0;
    static final String BEARER_PREFIX = "Bearer ";
    static final String ADMIN_ROLE = "admin";

    String provider = null;
    SSLContext sslContext = null;
    RolesProvider rolesProvider = null;
    Set<String> configuredIssuers = Collections.emptySet();
    Set<String> audiences = Collections.emptySet();
    Set<String> userNameClaims = Collections.emptySet();
    Set<String> externalMemberClaims = Collections.emptySet();
    String userDomainTemplate = DEFAULT_USER_DOMAIN_TEMPLATE;
    String externalMemberTemplate = DEFAULT_EXTERNAL_MEMBER_TEMPLATE;
    TokenExchangeIdentityProvider externalIdentityProvider = null;
    String fallbackJwksUri = null;
    long bootTimeOffsetSeconds = DEFAULT_BOOT_TIME_OFFSET_SECONDS;
    final JwtsHelper jwtsHelper = new JwtsHelper();
    final ConcurrentMap<String, IssuerConfig> issuerConfigs = new ConcurrentHashMap<>();

    @Override
    public Scheme getProviderScheme() {
        return Scheme.CLASS;
    }

    @Override
    public void setRolesProvider(final RolesProvider rolesProvider) {
        this.rolesProvider = rolesProvider;
    }

    @Override
    public void initialize(final String provider, final String providerEndpoint, final SSLContext sslContext,
            final KeyStore keyStore) {
        this.provider = provider;
        this.sslContext = sslContext;
        issuerConfigs.clear();

        audiences = parseCsvSet(System.getProperty(LOCAL_AGENT_PROP_AUDIENCE));
        if (audiences.isEmpty()) {
            throw new IllegalArgumentException("Local agent audience must be configured");
        }

        configuredIssuers = parseCsvSet(System.getProperty(LOCAL_AGENT_PROP_ISSUER));
        userNameClaims = resolveUserNameClaims();
        externalMemberClaims = parseCsvSet(System.getProperty(LOCAL_AGENT_PROP_EXTERNAL_MEMBER_CLAIMS,
                DEFAULT_EXTERNAL_MEMBER_CLAIMS));
        userDomainTemplate = System.getProperty(LOCAL_AGENT_PROP_USER_DOMAIN_TEMPLATE, DEFAULT_USER_DOMAIN_TEMPLATE);
        if (StringUtil.isEmpty(userDomainTemplate) || !userDomainTemplate.contains("%s")) {
            throw new IllegalArgumentException("User domain template must be configured and contain %s");
        }
        externalMemberTemplate = System.getProperty(LOCAL_AGENT_PROP_EXTERNAL_MEMBER_TEMPLATE,
                DEFAULT_EXTERNAL_MEMBER_TEMPLATE);
        if (StringUtil.isEmpty(externalMemberTemplate) || !externalMemberTemplate.contains("%s")) {
            throw new IllegalArgumentException("External member template must be configured and contain %s");
        }
        externalIdentityProvider = loadExternalIdentityProvider(
                System.getProperty(LOCAL_AGENT_PROP_EXTERNAL_IDENTITY_PROVIDER_CLASS));
        fallbackJwksUri = normalizeProperty(System.getProperty(LOCAL_AGENT_PROP_JWKS_URI));
        bootTimeOffsetSeconds = parseLong(System.getProperty(LOCAL_AGENT_PROP_BOOT_TIME_OFFSET),
                DEFAULT_BOOT_TIME_OFFSET_SECONDS);

        final Map<String, String> jwksUriMap = parseMap(System.getProperty(LOCAL_AGENT_PROP_JWKS_URI_MAP));
        for (String issuer : configuredIssuers) {
            issuerConfigs.put(issuer, new IssuerConfig(issuer, jwksUriMap.get(issuer)));
        }
        for (Map.Entry<String, String> entry : jwksUriMap.entrySet()) {
            issuerConfigs.put(entry.getKey(), new IssuerConfig(entry.getKey(), entry.getValue()));
        }
    }

    @Override
    public InstanceConfirmation confirmInstance(final InstanceConfirmation confirmation) throws ProviderResourceException {
        if (confirmation == null) {
            throw error("Instance confirmation request not provided", ProviderResourceException.BAD_REQUEST);
        }

        final String domain = normalizeDomain(confirmation.getDomain());
        final String service = confirmation.getService();
        if (StringUtil.isEmpty(domain) || StringUtil.isEmpty(service)) {
            throw error("Domain and service must be provided", ProviderResourceException.BAD_REQUEST);
        }

        final String attestationData = normalizeAttestationData(confirmation.getAttestationData());
        if (StringUtil.isEmpty(attestationData)) {
            throw error("Service credentials not provided", ProviderResourceException.FORBIDDEN);
        }

        final JWTClaimsSet claimsSet = validateToken(attestationData);
        if (!isAuthorizedForDomain(domain, claimsSet)) {
            throw error("ID token is not authorized for requested domain", ProviderResourceException.FORBIDDEN);
        }

        final Map<String, String> attributes = new HashMap<>();
        attributes.put(ZTS_CERT_REFRESH, "false");
        attributes.put(ZTS_CERT_USAGE, ZTS_CERT_USAGE_CLIENT);
        confirmation.setAttributes(attributes);
        return confirmation;
    }

    @Override
    public InstanceConfirmation refreshInstance(final InstanceConfirmation confirmation) throws ProviderResourceException {
        throw error("Local agent certificates cannot be refreshed", ProviderResourceException.FORBIDDEN);
    }

    JWTClaimsSet validateToken(final String token) throws ProviderResourceException {
        final String tokenIssuer = extractIssuer(token);
        final IssuerConfig issuerConfig = getIssuerConfig(tokenIssuer);
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
        validateTimeClaims(claimsSet);
        return claimsSet;
    }

    IssuerConfig getIssuerConfig(final String tokenIssuer) {
        IssuerConfig issuerConfig = issuerConfigs.get(tokenIssuer);
        if (issuerConfig != null) {
            return issuerConfig;
        }
        if (!configuredIssuers.isEmpty() && !configuredIssuers.contains(tokenIssuer)) {
            return null;
        }
        return issuerConfigs.computeIfAbsent(tokenIssuer, issuer ->
                new IssuerConfig(issuer, fallbackJwksUri));
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

    ConfigurableJWTProcessor<SecurityContext> getJwtProcessor(final IssuerConfig issuerConfig)
            throws ProviderResourceException {
        ConfigurableJWTProcessor<SecurityContext> processor = issuerConfig.jwtProcessor;
        if (processor != null) {
            return processor;
        }
        synchronized (issuerConfig) {
            processor = issuerConfig.jwtProcessor;
            if (processor != null) {
                return processor;
            }

            final String jwksUri = resolveJwksUri(issuerConfig);
            if (StringUtil.isEmpty(jwksUri)) {
                throw error("Unable to resolve JWKS URI for issuer: " + issuerConfig.issuer,
                        ProviderResourceException.FORBIDDEN);
            }

            issuerConfig.jwtProcessor = JwtsHelper.getJWTProcessor(new JwtsSigningKeyResolver(jwksUri, sslContext));
            return issuerConfig.jwtProcessor;
        }
    }

    String resolveJwksUri(final IssuerConfig issuerConfig) {
        final String discoveredJwksUri = extractIssuerJwksUri(issuerConfig.issuer);
        if (!StringUtil.isEmpty(discoveredJwksUri)) {
            return discoveredJwksUri;
        }
        if (!StringUtil.isEmpty(issuerConfig.fallbackJwksUri)) {
            return issuerConfig.fallbackJwksUri;
        }
        return fallbackJwksUri;
    }

    String extractIssuerJwksUri(final String issuer) {
        final String openIdConfigUri = buildOpenIdConfigUri(issuer);
        if (StringUtil.isEmpty(openIdConfigUri)) {
            return null;
        }
        return jwtsHelper.extractJwksUri(openIdConfigUri, sslContext);
    }

    String buildOpenIdConfigUri(final String issuer) {
        if (StringUtil.isEmpty(issuer)) {
            return null;
        }
        final String normalizedIssuer = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
        return normalizedIssuer + "/.well-known/openid-configuration";
    }

    void validateAudience(final JWTClaimsSet claimsSet) throws ProviderResourceException {
        if (audiences == null || audiences.isEmpty()) {
            throw error("Local agent audience not configured", ProviderResourceException.INTERNAL_SERVER_ERROR);
        }

        final List<String> audienceList = claimsSet.getAudience();
        final Set<String> tokenAudiences = audienceList == null ? Collections.emptySet() : new HashSet<>(audienceList);
        if (tokenAudiences.stream().noneMatch(audiences::contains)) {
            throw error("Token audience is not configured local agent audience: " + tokenAudiences,
                    ProviderResourceException.FORBIDDEN);
        }
    }

    void validateTimeClaims(final JWTClaimsSet claimsSet) throws ProviderResourceException {
        final long nowMillis = System.currentTimeMillis();
        final Date expirationTime = claimsSet.getExpirationTime();
        if (expirationTime == null) {
            throw error("Token does not contain required exp claim", ProviderResourceException.FORBIDDEN);
        }
        if (expirationTime.getTime() <= nowMillis) {
            throw error("Token is expired, expired at: " + expirationTime, ProviderResourceException.FORBIDDEN);
        }

        final Date notBeforeTime = claimsSet.getNotBeforeTime();
        if (notBeforeTime != null && notBeforeTime.getTime() > nowMillis) {
            throw error("Token is not valid yet, not before: " + notBeforeTime, ProviderResourceException.FORBIDDEN);
        }

        if (bootTimeOffsetSeconds <= 0) {
            return;
        }
        final Date issueTime = claimsSet.getIssueTime();
        if (issueTime == null || issueTime.getTime() < nowMillis - TimeUnit.SECONDS.toMillis(bootTimeOffsetSeconds) ||
                issueTime.getTime() > nowMillis + TimeUnit.SECONDS.toMillis(bootTimeOffsetSeconds)) {
            throw error("Token issue time is not recent enough, issued at: " + issueTime,
                    ProviderResourceException.FORBIDDEN);
        }
    }

    boolean isAuthorizedForDomain(final String domain, final JWTClaimsSet claimsSet) throws ProviderResourceException {
        final String userName = extractAuthenticatedUserName(claimsSet);
        if (!StringUtil.isEmpty(userName) && isDomainInScope(domain, buildUserRootDomain(userName))) {
            return true;
        }
        return isExternalMemberDomainAdmin(domain, extractExternalMemberNames(claimsSet));
    }

    String extractAuthenticatedUserName(final JWTClaimsSet claimsSet) {
        for (String claim : userNameClaims) {
            final String userName = normalizeUserName(claimValueToString(claimsSet.getClaim(claim)));
            if (!StringUtil.isEmpty(userName)) {
                return userName;
            }
        }
        return null;
    }

    Set<String> extractExternalMemberNames(final JWTClaimsSet claimsSet) {
        if ((externalMemberClaims == null || externalMemberClaims.isEmpty()) && externalIdentityProvider == null) {
            return Collections.emptySet();
        }

        final Set<String> memberNames = new LinkedHashSet<>();
        if (externalIdentityProvider != null) {
            try {
                addExternalMemberName(memberNames,
                        externalIdentityProvider.getTokenIdentity(new ClaimsOAuth2Token(claimsSet)));
            } catch (Exception ex) {
                LOG.warn("Unable to resolve external identity provider member name: {}", ex.getMessage());
            }
        }
        if (externalMemberClaims == null) {
            return memberNames;
        }
        for (String claim : externalMemberClaims) {
            addClaimMemberNames(memberNames, claimsSet.getClaim(claim));
        }
        return memberNames;
    }

    void addClaimMemberNames(final Set<String> memberNames, final Object claimValue) {
        if (claimValue == null) {
            return;
        }
        if (claimValue instanceof Collection<?>) {
            for (Object value : (Collection<?>) claimValue) {
                addExternalMemberName(memberNames, claimValueToString(value));
            }
            return;
        }
        addExternalMemberName(memberNames, claimValueToString(claimValue));
    }

    void addExternalMemberName(final Set<String> memberNames, final String memberName) {
        final String normalizedMemberName = normalizeMemberName(memberName);
        if (StringUtil.isEmpty(normalizedMemberName)) {
            return;
        }
        memberNames.add(normalizedMemberName);
        final String templatedMemberName = normalizeMemberName(
                externalMemberTemplate.replace("%s", normalizedMemberName));
        if (!StringUtil.isEmpty(templatedMemberName)) {
            memberNames.add(templatedMemberName);
        }
    }

    String claimValueToString(final Object claimValue) {
        if (claimValue == null) {
            return null;
        }
        final String value = claimValue.toString().trim();
        return value.isEmpty() ? null : value;
    }

    boolean isExternalMemberDomainAdmin(final String domain, final Set<String> memberNames) throws ProviderResourceException {
        if (rolesProvider == null || memberNames == null || memberNames.isEmpty()) {
            return false;
        }

        for (String memberName : memberNames) {
            if (isDomainAdminMember(domain, memberName)) {
                return true;
            }
        }
        return false;
    }

    boolean isDomainAdminMember(final String domain, final String memberName) throws ProviderResourceException {
        try {
            final Set<String> roles = rolesProvider.getRolesForPrincipal(domain, memberName);
            if (containsAdminRole(domain, roles)) {
                return true;
            }
        } catch (UnsupportedOperationException ex) {
            return isDirectAdminRoleMember(domain, memberName);
        } catch (Exception ex) {
            throw error("Unable to lookup domain admin role membership: " + ex.getMessage(),
                    ProviderResourceException.INTERNAL_SERVER_ERROR);
        }
        return false;
    }

    boolean containsAdminRole(final String domain, final Set<String> roles) {
        if (roles == null || roles.isEmpty()) {
            return false;
        }
        return roles.contains(ADMIN_ROLE) || roles.contains(domain + ":role." + ADMIN_ROLE);
    }

    boolean isDirectAdminRoleMember(final String domain, final String memberName) throws ProviderResourceException {
        final List<Role> roles;
        try {
            roles = rolesProvider.getRolesByDomain(domain);
        } catch (Exception ex) {
            throw error("Unable to lookup domain roles: " + ex.getMessage(),
                    ProviderResourceException.INTERNAL_SERVER_ERROR);
        }
        if (roles == null || roles.isEmpty()) {
            return false;
        }

        for (Role role : roles) {
            if (!isAdminRole(domain, role)) {
                continue;
            }
            final List<RoleMember> roleMembers = role.getRoleMembers();
            if (roleMembers == null) {
                continue;
            }
            for (RoleMember roleMember : roleMembers) {
                if (isActiveRoleMember(roleMember) &&
                        Objects.equals(normalizeMemberName(roleMember.getMemberName()), memberName)) {
                    return true;
                }
            }
        }
        return false;
    }

    boolean isAdminRole(final String domain, final Role role) {
        if (role == null || StringUtil.isEmpty(role.getName())) {
            return false;
        }
        return role.getName().equals(ADMIN_ROLE) || role.getName().equals(domain + ":role." + ADMIN_ROLE);
    }

    boolean isActiveRoleMember(final RoleMember roleMember) {
        if (roleMember == null || StringUtil.isEmpty(roleMember.getMemberName())) {
            return false;
        }
        if (Boolean.FALSE.equals(roleMember.getActive()) || Boolean.FALSE.equals(roleMember.getApproved())) {
            return false;
        }
        final Integer systemDisabled = roleMember.getSystemDisabled();
        if (systemDisabled != null && systemDisabled != 0) {
            return false;
        }
        return roleMember.getExpiration() == null || roleMember.getExpiration().millis() > System.currentTimeMillis();
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

    String normalizeMemberName(final String memberName) {
        if (StringUtil.isEmpty(memberName)) {
            return null;
        }
        final String normalizedMemberName = memberName.trim().toLowerCase(Locale.ROOT);
        return normalizedMemberName.isEmpty() ? null : normalizedMemberName;
    }

    String normalizeDomain(final String domain) {
        if (StringUtil.isEmpty(domain)) {
            return null;
        }
        final String normalizedDomain = domain.trim().toLowerCase(Locale.ROOT);
        return normalizedDomain.isEmpty() ? null : normalizedDomain;
    }

    String normalizeProperty(final String propertyValue) {
        if (StringUtil.isEmpty(propertyValue)) {
            return null;
        }
        final String normalizedValue = propertyValue.trim();
        return normalizedValue.isEmpty() ? null : normalizedValue;
    }

    Set<String> resolveUserNameClaims() {
        final String userNameClaim = normalizeProperty(System.getProperty(LOCAL_AGENT_PROP_USER_NAME_CLAIM));
        if (!StringUtil.isEmpty(userNameClaim)) {
            return Collections.singleton(userNameClaim);
        }
        return parseCsvSet(System.getProperty(LOCAL_AGENT_PROP_USER_NAME_CLAIMS, DEFAULT_USER_NAME_CLAIMS));
    }

    TokenExchangeIdentityProvider loadExternalIdentityProvider(final String className) {
        final String normalizedClassName = normalizeProperty(className);
        if (StringUtil.isEmpty(normalizedClassName)) {
            return null;
        }
        try {
            final Object providerObject = Class.forName(normalizedClassName).getConstructor().newInstance();
            if (!(providerObject instanceof TokenExchangeIdentityProvider)) {
                throw new IllegalArgumentException(normalizedClassName +
                        " does not implement TokenExchangeIdentityProvider");
            }
            return (TokenExchangeIdentityProvider) providerObject;
        } catch (IllegalArgumentException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalArgumentException("Unable to initialize external identity provider: " +
                    normalizedClassName, ex);
        }
    }

    Set<String> parseCsvSet(final String propertyValue) {
        if (StringUtil.isEmpty(propertyValue)) {
            return Collections.emptySet();
        }
        final Set<String> values = new LinkedHashSet<>();
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
                LOG.warn("Ignoring invalid local agent map entry: {}", entry);
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
            return Long.parseLong(propertyValue.trim());
        } catch (NumberFormatException ex) {
            LOG.warn("Invalid local agent long property value: {}, using default: {}", propertyValue, defaultValue);
            return defaultValue;
        }
    }

    private ProviderResourceException error(final String message, final int code) {
        LOG.error(message);
        return new ProviderResourceException(code, message);
    }

    static final class IssuerConfig {

        final String issuer;
        final String fallbackJwksUri;
        volatile ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

        IssuerConfig(final String issuer, final String fallbackJwksUri) {
            this.issuer = Objects.requireNonNull(issuer);
            this.fallbackJwksUri = fallbackJwksUri;
        }
    }

    static final class ClaimsOAuth2Token extends OAuth2Token {

        private final JWTClaimsSet claimsSet;

        ClaimsOAuth2Token(final JWTClaimsSet claimsSet) {
            this.claimsSet = claimsSet;
        }

        @Override
        public String getAudience() {
            final List<String> audiences = claimsSet.getAudience();
            return audiences == null || audiences.isEmpty() ? null : audiences.get(0);
        }

        @Override
        public String getIssuer() {
            return claimsSet.getIssuer();
        }

        @Override
        public String getSubject() {
            return claimsSet.getSubject();
        }

        @Override
        public long getExpiryTime() {
            return parseDateValueSeconds(claimsSet.getExpirationTime());
        }

        @Override
        public long getIssueTime() {
            return parseDateValueSeconds(claimsSet.getIssueTime());
        }

        @Override
        public long getNotBeforeTime() {
            return parseDateValueSeconds(claimsSet.getNotBeforeTime());
        }

        @Override
        public Object getClaim(final String name) {
            return claimsSet.getClaim(name);
        }

        long parseDateValueSeconds(final Date date) {
            return date == null ? 0 : date.getTime() / 1000;
        }
    }
}
