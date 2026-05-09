package com.yahoo.athenz.auth.impl;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.Date;
import java.util.concurrent.TimeUnit;

public class OIDCJwtAuthority implements Authority {

    private static final Logger LOG = LoggerFactory.getLogger(OIDCJwtAuthority.class);

    public static final String OIDC_JWT_DEFAULT = "Authorization";
    public static final String ATHENZ_PROP_OIDC_JWT = "athenz.auth.principal.auth.oidc.jwt";
    public static final String ATHENZ_PROP_OIDC_JWT_DOMAIN = "athenz.auth.principal.auth.oidc.jwt.domain";
    public static final String ATHENZ_PROP_OIDC_JWT_BOOT_TIME_OFFSET = "athenz.auth.principal.auth.oidc.jwt.boot_time_offset";
    public static final String ATHENZ_PROP_OIDC_JWT_AUDIENCE = "athenz.auth.principal.auth.oidc.jwt.audience";
    public static final String ATHENZ_PROP_OIDC_JWT_ISSUER = "athenz.auth.principal.auth.oidc.jwt.issuer";
    public static final String ATHENZ_PROP_OIDC_JWT_JWKS_URI = "athenz.auth.principal.auth.oidc.jwt.jwks_uri";
    public static final String ATHENZ_PROP_OIDC_JWT_CLAIM = "athenz.auth.principal.auth.oidc.jwt.claim";

    static final String AUTH_DOMAIN_DEFAULT = "user";
    static final String ISSUER = "https://athenz-zts-server.athenz:4443/zts/v1";
    static final String AUDIENCE = "athenz";
    static final String ISSUER_JWKS_URI = "https://athenz-zts-server.athenz:4443/zts/v1/.well-known/jwks";
    static final String CLAIM_SUB = "sub";
    static final String BEARER_PREFIX = "Bearer ";
    static final long DEFAULT_BOOT_TIME_OFFSET_SECONDS = TimeUnit.SECONDS.convert(5, TimeUnit.MINUTES);

    String principalDomain = AUTH_DOMAIN_DEFAULT;
    String jwtIssuer = ISSUER;
    String audience = AUDIENCE;
    String principalClaim = CLAIM_SUB;
    String headerName = OIDC_JWT_DEFAULT;
    long bootTimeOffsetSeconds = DEFAULT_BOOT_TIME_OFFSET_SECONDS;
    final JwtsHelper jwtsHelper = new JwtsHelper();
    volatile ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

    @Override
    public void initialize() {
        headerName = System.getProperty(ATHENZ_PROP_OIDC_JWT, OIDC_JWT_DEFAULT);
        principalDomain = System.getProperty(ATHENZ_PROP_OIDC_JWT_DOMAIN, AUTH_DOMAIN_DEFAULT);
        jwtIssuer = System.getProperty(ATHENZ_PROP_OIDC_JWT_ISSUER, ISSUER);
        audience = System.getProperty(ATHENZ_PROP_OIDC_JWT_AUDIENCE, AUDIENCE);
        principalClaim = System.getProperty(ATHENZ_PROP_OIDC_JWT_CLAIM, CLAIM_SUB);
        bootTimeOffsetSeconds = parseBootTimeOffsetSeconds(System.getProperty(ATHENZ_PROP_OIDC_JWT_BOOT_TIME_OFFSET));
        jwtProcessor = null;
    }

    @Override
    public String getID() {
        return "Jwt";
    }

    @Override
    public String getDomain() {
        return principalDomain;
    }

    @Override
    public String getHeader() {
        return headerName;
    }

    @Override
    public String getAuthenticateChallenge() {
        return "Bearer realm=\"athenz\"";
    }

    @Override
    public Principal authenticate(String creds, String remoteAddr, String httpMethod, StringBuilder errMsg) {
        errMsg = errMsg == null ? new StringBuilder(512) : errMsg;

        if (creds == null || !creds.startsWith(BEARER_PREFIX)) {
            errMsg.append("OIDCJwtAuthority:authenticate: credentials do not start with Bearer");
            return null;
        }

        final String token = creds.substring(BEARER_PREFIX.length());
        if (token.isEmpty()) {
            errMsg.append("OIDCJwtAuthority:authenticate: token is empty");
            return null;
        }

        final String tokenIssuer = extractIssuer(token, errMsg);
        if (tokenIssuer == null) {
            return null;
        }

        if (!jwtIssuer.equals(tokenIssuer)) {
            errMsg.append("token issuer is not the configured issuer: ").append(tokenIssuer);
            return null;
        }

        final ConfigurableJWTProcessor<SecurityContext> jwtProcessor = getJwtProcessor(errMsg);
        if (jwtProcessor == null) {
            return null;
        }

        JWTClaimsSet claimsSet;
        try {
            claimsSet = jwtProcessor.process(token, null);
        } catch (Exception ex) {
            errMsg.append("Unable to parse and validate token: ").append(ex.getMessage());
            return null;
        }

        if (!audience.equals(JwtsHelper.getAudience(claimsSet))) {
            errMsg.append("token audience is not ZTS Server audience: ").append(JwtsHelper.getAudience(claimsSet));
            return null;
        }

        Date issueDate = claimsSet.getIssueTime();
        if (issueDate == null || issueDate.getTime() < System.currentTimeMillis() -
                TimeUnit.SECONDS.toMillis(bootTimeOffsetSeconds)) {
            errMsg.append("token issue time is not recent enough, issued at: ").append(issueDate);
            return null;
        }

        final String principalName = extractPrincipalName(claimsSet, errMsg);
        if (principalName == null) {
            return null;
        }

        SimplePrincipal principal = getSimplePrincipal(principalName.toLowerCase(), creds, issueDate.getTime() / 1000);
        if (principal == null) {
            errMsg.append("OIDCJwtAuthority:authenticate: failed to create principal: claim=")
                    .append(principalClaim).append(" value=").append(principalName);
            LOG.error(errMsg.toString());
            return null;
        }
        principal.setUnsignedCreds(creds);
        return principal;
    }

    String extractIssuer(final String token, StringBuilder errMsg) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            final String issuer = signedJWT.getJWTClaimsSet().getIssuer();
            if (StringUtil.isEmpty(issuer)) {
                errMsg.append("token does not contain required iss claim");
                return null;
            }
            return issuer;
        } catch (ParseException ex) {
            errMsg.append("Unable to parse token: ").append(ex.getMessage());
            return null;
        }
    }

    long parseBootTimeOffsetSeconds(final String bootTimeOffset) {
        if (StringUtil.isEmpty(bootTimeOffset)) {
            return DEFAULT_BOOT_TIME_OFFSET_SECONDS;
        }
        try {
            return Long.parseLong(bootTimeOffset);
        } catch (NumberFormatException ex) {
            LOG.warn("Invalid OIDC JWT boot time offset configured: {}, using default: {}",
                    bootTimeOffset, DEFAULT_BOOT_TIME_OFFSET_SECONDS);
            return DEFAULT_BOOT_TIME_OFFSET_SECONDS;
        }
    }

    ConfigurableJWTProcessor<SecurityContext> getJwtProcessor(StringBuilder errMsg) {
        ConfigurableJWTProcessor<SecurityContext> processor = jwtProcessor;
        if (processor != null) {
            return processor;
        }
        synchronized (this) {
            processor = jwtProcessor;
            if (processor != null) {
                return processor;
            }
            processor = buildJwtProcessor(errMsg);
            if (processor != null) {
                jwtProcessor = processor;
            }
            return processor;
        }
    }

    ConfigurableJWTProcessor<SecurityContext> buildJwtProcessor(StringBuilder errMsg) {
        String jwksUri = extractIssuerJwksUri(jwtIssuer);

        if (StringUtil.isEmpty(jwksUri)) {
            jwksUri = extractFallbackJwksUri();
            if (StringUtil.isEmpty(jwksUri)) {
                errMsg.append("JWT Processor not initialized");
                return null;
            }
        }
        return JwtsHelper.getJWTProcessor(new JwtsSigningKeyResolver(jwksUri, null));
    }

    String extractIssuerJwksUri(final String issuer) {
        final String openIdConfigUri = buildOpenIdConfigUri(issuer);
        if (StringUtil.isEmpty(openIdConfigUri)) {
            return null;
        }
        return jwtsHelper.extractJwksUri(openIdConfigUri, null);
    }

    String buildOpenIdConfigUri(final String issuer) {
        if (StringUtil.isEmpty(issuer)) {
            return null;
        }
        return issuer + "/.well-known/openid-configuration";
    }

    String extractFallbackJwksUri() {
        String jwksUri = System.getProperty(ATHENZ_PROP_OIDC_JWT_JWKS_URI);
        if (!StringUtil.isEmpty(jwksUri)) {
            return jwksUri;
        }
        jwksUri = extractIssuerJwksUri(jwtIssuer);
        return StringUtil.isEmpty(jwksUri) ? ISSUER_JWKS_URI : jwksUri;
    }

    SimplePrincipal getSimplePrincipal(String name, String creds, long issueTime) {
        return (SimplePrincipal) SimplePrincipal.create(getDomain(),
                name, creds, issueTime, this);
    }

    String extractPrincipalName(final JWTClaimsSet claimsSet, StringBuilder errMsg) {
        final String principalName = JwtsHelper.getStringClaim(claimsSet, principalClaim);
        if (StringUtil.isEmpty(principalName)) {
            errMsg.append("token does not contain required ").append(principalClaim).append(" claim");
            return null;
        }
        return principalName;
    }
}
