package com.yahoo.athenz.auth.impl;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import com.yahoo.athenz.auth.util.GlobStringsMatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

import static com.yahoo.athenz.auth.AuthorityConsts.ATHENZ_PROP_RESTRICTED_OU;

/**
 * Authenticates an mTLS client certificate whose service identity is in a SPIFFE URI SAN.
 * The TLS server is responsible for validating the certificate chain and validity period.
 */
public class SPIFFECertificateAuthority implements Authority {

    private static final Logger LOG = LoggerFactory.getLogger(SPIFFECertificateAuthority.class);

    public static final String PROP_AUTHORIZED_TRUST_DOMAINS =
            "athenz.auth.certificate.spiffe.authorized_trust_domains";
    public static final String PROP_ALLOW_GLOBAL_SPIFFE_ID =
            "athenz.auth.certificate.spiffe.allow_global_spiffe_id";
    public static final String PROP_NAMESPACE_AS_DOMAIN =
            "athenz.auth.certificate.spiffe.namespace_as_domain";
    public static final String PROP_EXCLUDED_PRINCIPALS =
            "athenz.auth.certificate.spiffe.excluded_principals";

    private static final String PROP_ATHENZ_EXCLUDED_PRINCIPALS =
            "athenz.auth.certificate.excluded_principals";
    private static final String CHALLENGE = "AthenzX509Certificate realm=\"spiffe\"";
    private static final String SPIFFE_SCHEME_PREFIX = "spiffe:";
    private static final Pattern COMPOUND_NAME = Pattern.compile(
            "[a-zA-Z0-9_][a-zA-Z0-9_-]*(\\.[a-zA-Z0-9_][a-zA-Z0-9_-]*)*");

    private final GlobStringsMatcher restrictedOuMatcher = new GlobStringsMatcher(ATHENZ_PROP_RESTRICTED_OU);
    private Set<String> authorizedTrustDomains = Set.of();
    private Set<String> excludedPrincipals = Set.of();
    private boolean allowGlobalSpiffeId;
    private boolean namespaceAsDomain;
    private CertificateAuthorityValidator authorityValidator;

    @Override
    public void initialize() {
        authorizedTrustDomains = parseNames(System.getProperty(PROP_AUTHORIZED_TRUST_DOMAINS));
        Set<String> exclusions = new HashSet<>(parseNames(System.getProperty(PROP_ATHENZ_EXCLUDED_PRINCIPALS)));
        exclusions.addAll(parseNames(System.getProperty(PROP_EXCLUDED_PRINCIPALS)));
        excludedPrincipals = Set.copyOf(exclusions);
        allowGlobalSpiffeId = Boolean.parseBoolean(System.getProperty(PROP_ALLOW_GLOBAL_SPIFFE_ID, "false"));
        namespaceAsDomain = Boolean.parseBoolean(System.getProperty(PROP_NAMESPACE_AS_DOMAIN, "false"));
        authorityValidator = new CertificateAuthorityValidator();
    }

    private static Set<String> parseNames(String value) {
        if (value == null || value.isBlank()) {
            return Set.of();
        }
        Set<String> names = new HashSet<>();
        for (String item : value.split(",")) {
            String name = item.trim().toLowerCase(Locale.ROOT);
            if (!name.isEmpty()) {
                names.add(name);
            }
        }
        return Set.copyOf(names);
    }

    @Override
    public String getID() {
        return "Auth-SPIFFE-X509";
    }

    @Override
    public String getDomain() {
        return null;
    }

    @Override
    public String getHeader() {
        return null;
    }

    @Override
    public String getAuthenticateChallenge() {
        return CHALLENGE;
    }

    @Override
    public CredSource getCredSource() {
        return CredSource.CERTIFICATE;
    }

    @Override
    public Principal authenticate(String creds, String remoteAddr, String httpMethod, StringBuilder errMsg) {
        return null;
    }

    @Override
    public Principal authenticate(X509Certificate[] certs, StringBuilder errMsg) {
        if (certs == null || certs.length == 0 || certs[0] == null) {
            reportError("No certificate available in request", errMsg);
            return null;
        }

        X509Certificate cert = certs[0];
        final String commonName;
        try {
            commonName = Crypto.extractX509CertCommonName(cert);
        } catch (CryptoException ex) {
            reportError("Invalid certificate subject", errMsg);
            return null;
        }
        if (commonName != null) {
            reportError("Certificate subject must not contain a Common Name", errMsg);
            return null;
        }
        if (authorityValidator == null || !authorityValidator.validate(cert)) {
            reportError("Certificate issuer does not match the configured trust store", errMsg);
            return null;
        }

        String spiffeId = null;
        for (String sanUri : Crypto.extractX509CertURIs(cert)) {
            if (sanUri == null || !sanUri.regionMatches(true, 0, SPIFFE_SCHEME_PREFIX, 0,
                    SPIFFE_SCHEME_PREFIX.length())) {
                continue;
            }
            if (spiffeId != null) {
                reportError("Certificate has multiple SPIFFE IDs", errMsg);
                return null;
            }
            spiffeId = sanUri;
        }
        if (spiffeId == null) {
            reportError("Certificate does not have a SPIFFE ID", errMsg);
            return null;
        }

        ServiceIdentity identity = parseServiceIdentity(spiffeId);
        if (identity == null) {
            reportError("Invalid or unauthorized SPIFFE ID", errMsg);
            return null;
        }
        String fullName = identity.domain() + "." + identity.service();
        if (excludedPrincipals.contains(fullName)) {
            reportError("Principal is excluded", errMsg);
            return null;
        }

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create(identity.domain(),
                identity.service(), cert.toString(), this);
        if (principal == null) {
            reportError("Unable to create certificate principal", errMsg);
            return null;
        }
        // X.509-SVID subjects may be empty. Keep the authenticated identity in audit logs.
        principal.setUnsignedCreds(fullName);
        principal.setX509Certificate(cert);
        try {
            principal.setMtlsRestricted(Crypto.isRestrictedCertificate(cert, restrictedOuMatcher));
        } catch (CryptoException ex) {
            reportError("Invalid certificate subject", errMsg);
            return null;
        }
        return principal;
    }

    private ServiceIdentity parseServiceIdentity(String spiffeId) {
        final URI uri;
        try {
            uri = new URI(spiffeId);
        } catch (URISyntaxException ex) {
            return null;
        }

        // Reject URI components and escapes that could produce more than one identity
        // representation or change the meaning of a path segment.
        String trustDomain = uri.getRawAuthority();
        String path = uri.getRawPath();
        if (!"spiffe".equalsIgnoreCase(uri.getScheme()) || uri.isOpaque()
                || !isCompoundName(trustDomain, 512) || path == null
                || !path.equals(uri.getPath()) || uri.getRawQuery() != null
                || uri.getRawFragment() != null) {
            return null;
        }

        String[] parts = path.split("/", -1);
        String domain;
        String service;
        if (parts.length == 5 && parts[0].isEmpty() && "ns".equals(parts[1])
                && isCompoundName(parts[2], 512) && "sa".equals(parts[3])) {
            if (!authorizedTrustDomains.contains(trustDomain.toLowerCase(Locale.ROOT))) {
                return null;
            }
            if (namespaceAsDomain) {
                domain = parts[2];
                service = parts[4];
            } else {
                int delimiter = parts[4].lastIndexOf('.');
                if (delimiter < 1) {
                    return null;
                }
                domain = parts[4].substring(0, delimiter);
                service = parts[4].substring(delimiter + 1);
            }
        } else if (allowGlobalSpiffeId && parts.length == 3 && parts[0].isEmpty()
                && "sa".equals(parts[1])) {
            domain = trustDomain;
            service = parts[2];
        } else {
            return null;
        }

        if (!isCompoundName(domain, 512) || !isCompoundName(service, 1024)) {
            return null;
        }
        return new ServiceIdentity(domain.toLowerCase(Locale.ROOT), service.toLowerCase(Locale.ROOT));
    }

    private static boolean isCompoundName(String value, int maxLength) {
        return value != null && value.length() <= maxLength && COMPOUND_NAME.matcher(value).matches();
    }

    private void reportError(String message, StringBuilder errMsg) {
        LOG.debug("SPIFFECertificateAuthority: {}", message);
        if (errMsg != null) {
            errMsg.append("SPIFFECertificateAuthority: ").append(message);
        }
    }

    private record ServiceIdentity(String domain, String service) {
    }
}
