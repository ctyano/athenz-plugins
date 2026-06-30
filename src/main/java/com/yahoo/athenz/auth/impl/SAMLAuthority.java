package com.yahoo.athenz.auth.impl;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import jakarta.servlet.http.HttpServletRequest;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

/**
 * Authority implementation for validating SAML 2.0 Response or Assertion
 * credentials and mapping the verified subject to an Athenz principal.
 *
 * <p>Operational limitations:
 * <ul>
 *   <li>This class does not implement a complete SAML SP flow. It does not
 *       generate AuthnRequest messages, manage RelayState, provide an ACS
 *       endpoint, or validate InResponseTo against a request store.</li>
 *   <li>Replay protection is in-memory and local to this JVM. In a clustered
 *       ZMS deployment, assertion replay detection is not shared across
 *       nodes unless an external shared cache is added outside this class.</li>
 *   <li>IdP signing certificates are loaded at initialization time. Certificate
 *       rotation requires reinitializing this authority or restarting the
 *       process unless the surrounding deployment provides a reload mechanism.</li>
 *   <li>Certificate revocation status is not checked. Trust is based on the
 *       configured certificate bundle and certificate validity dates.</li>
 *   <li>Network and transport protections, such as TLS termination, header
 *       stripping at proxies, and restricting who may supply SAML headers or
 *       request parameters, must be enforced by the surrounding deployment.</li>
 * </ul>
 */
public class SAMLAuthority implements Authority {

    private static final Logger LOG = LoggerFactory.getLogger(SAMLAuthority.class);

    public static final String DEFAULT_PROPERTY_PREFIX = "athenz.auth.saml";

    public static final String PROP_HEADER = "header";
    public static final String PROP_CRED_SOURCE = "cred_source";
    public static final String PROP_REQUEST_PARAMETER = "request_parameter";
    public static final String PROP_DOMAIN = "domain";
    public static final String PROP_ISSUER = "issuer";
    public static final String PROP_AUDIENCE = "audience";
    public static final String PROP_CERTIFICATE_FILE = "certificate_file";
    public static final String PROP_NAME_ATTRIBUTE = "name_attribute";
    public static final String PROP_NAME_ID_FORMAT = "name_id_format";
    public static final String PROP_RECIPIENT = "recipient";
    public static final String PROP_CLOCK_SKEW = "clock_skew";
    public static final String PROP_MAX_MESSAGE_SIZE = "max_message_size";
    public static final String PROP_MAX_ASSERTION_TTL = "max_assertion_ttl";
    public static final String PROP_PRINCIPAL_PATTERN = "principal_pattern";
    public static final String PROP_REPLAY_CACHE = "replay_cache";
    public static final String PROP_REPLAY_CACHE_MAX_ENTRIES = "replay_cache_max_entries";
    public static final String PROP_ALLOWED_SIGNATURE_ALGORITHMS = "allowed_signature_algorithms";
    public static final String PROP_ALLOWED_DIGEST_ALGORITHMS = "allowed_digest_algorithms";

    public static final String DEFAULT_HEADER = "X-SAML-Assertion";
    public static final String DEFAULT_REQUEST_PARAMETER = "SAMLResponse";
    public static final String DEFAULT_DOMAIN = "user";
    public static final long DEFAULT_CLOCK_SKEW_SECONDS = TimeUnit.SECONDS.convert(2, TimeUnit.MINUTES);
    public static final int DEFAULT_MAX_MESSAGE_SIZE_BYTES = 2 * 1024 * 1024;
    public static final long DEFAULT_MAX_ASSERTION_TTL_SECONDS = TimeUnit.SECONDS.convert(1, TimeUnit.HOURS);
    public static final String DEFAULT_PRINCIPAL_PATTERN = "[a-z0-9][a-z0-9._@-]*";
    public static final boolean DEFAULT_REPLAY_CACHE_ENABLED = true;
    public static final int DEFAULT_REPLAY_CACHE_MAX_ENTRIES = 10000;

    static final String AUTHORITY_ID = "Auth-SAML";
    static final String SAML_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
    static final String SAML_PROTOCOL_NS = "urn:oasis:names:tc:SAML:2.0:protocol";
    static final String XML_SIGNATURE_NS = XMLSignature.XMLNS;
    static final String SAML_SUCCESS_STATUS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    static final String SAML_BEARER_METHOD = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
    static final String DEFAULT_ALLOWED_SIGNATURE_ALGORITHMS =
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256," +
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384," +
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512," +
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256," +
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384," +
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
    static final String DEFAULT_ALLOWED_DIGEST_ALGORITHMS =
            "http://www.w3.org/2001/04/xmlenc#sha256," +
            "http://www.w3.org/2001/04/xmldsig-more#sha384," +
            "http://www.w3.org/2001/04/xmlenc#sha512";

    String headerName = DEFAULT_HEADER;
    String requestParameter = DEFAULT_REQUEST_PARAMETER;
    String principalDomain = DEFAULT_DOMAIN;
    String expectedIssuer;
    String expectedAudience;
    String certificateFile;
    String principalNameAttribute;
    String expectedNameIdFormat;
    String expectedRecipient;
    long clockSkewSeconds = DEFAULT_CLOCK_SKEW_SECONDS;
    int maxMessageSizeBytes = DEFAULT_MAX_MESSAGE_SIZE_BYTES;
    long maxAssertionTtlSeconds = DEFAULT_MAX_ASSERTION_TTL_SECONDS;
    boolean replayCacheEnabled = DEFAULT_REPLAY_CACHE_ENABLED;
    int replayCacheMaxEntries = DEFAULT_REPLAY_CACHE_MAX_ENTRIES;
    CredSource credSource = CredSource.HEADER;
    X509Certificate[] trustedCertificates = new X509Certificate[0];
    Pattern principalPattern = Pattern.compile(DEFAULT_PRINCIPAL_PATTERN);
    Set<String> allowedSignatureAlgorithms = parseCsvSet(DEFAULT_ALLOWED_SIGNATURE_ALGORITHMS);
    Set<String> allowedDigestAlgorithms = parseCsvSet(DEFAULT_ALLOWED_DIGEST_ALGORITHMS);
    final Map<String, Long> replayCache = new ConcurrentHashMap<>();

    protected String propertyPrefix() {
        return DEFAULT_PROPERTY_PREFIX;
    }

    @Override
    public void initialize() {

        final String prefix = propertyPrefix();
        headerName = System.getProperty(prefix + "." + PROP_HEADER, DEFAULT_HEADER);
        requestParameter = System.getProperty(prefix + "." + PROP_REQUEST_PARAMETER, DEFAULT_REQUEST_PARAMETER);
        principalDomain = System.getProperty(prefix + "." + PROP_DOMAIN, DEFAULT_DOMAIN);
        expectedIssuer = System.getProperty(prefix + "." + PROP_ISSUER);
        expectedAudience = System.getProperty(prefix + "." + PROP_AUDIENCE);
        certificateFile = System.getProperty(prefix + "." + PROP_CERTIFICATE_FILE);
        principalNameAttribute = System.getProperty(prefix + "." + PROP_NAME_ATTRIBUTE);
        expectedNameIdFormat = System.getProperty(prefix + "." + PROP_NAME_ID_FORMAT);
        expectedRecipient = System.getProperty(prefix + "." + PROP_RECIPIENT);
        clockSkewSeconds = parseClockSkewSeconds(System.getProperty(prefix + "." + PROP_CLOCK_SKEW));
        maxMessageSizeBytes = parsePositiveInt(System.getProperty(prefix + "." + PROP_MAX_MESSAGE_SIZE),
                DEFAULT_MAX_MESSAGE_SIZE_BYTES, PROP_MAX_MESSAGE_SIZE);
        maxAssertionTtlSeconds = parseLong(System.getProperty(prefix + "." + PROP_MAX_ASSERTION_TTL),
                DEFAULT_MAX_ASSERTION_TTL_SECONDS, PROP_MAX_ASSERTION_TTL);
        replayCacheEnabled = Boolean.parseBoolean(System.getProperty(prefix + "." + PROP_REPLAY_CACHE,
                Boolean.toString(DEFAULT_REPLAY_CACHE_ENABLED)));
        replayCacheMaxEntries = parsePositiveInt(System.getProperty(prefix + "." + PROP_REPLAY_CACHE_MAX_ENTRIES),
                DEFAULT_REPLAY_CACHE_MAX_ENTRIES, PROP_REPLAY_CACHE_MAX_ENTRIES);
        principalPattern = parsePrincipalPattern(System.getProperty(prefix + "." + PROP_PRINCIPAL_PATTERN,
                DEFAULT_PRINCIPAL_PATTERN), prefix);
        allowedSignatureAlgorithms = parseCsvSet(System.getProperty(prefix + "." + PROP_ALLOWED_SIGNATURE_ALGORITHMS,
                DEFAULT_ALLOWED_SIGNATURE_ALGORITHMS));
        allowedDigestAlgorithms = parseCsvSet(System.getProperty(prefix + "." + PROP_ALLOWED_DIGEST_ALGORITHMS,
                DEFAULT_ALLOWED_DIGEST_ALGORITHMS));
        credSource = parseCredSource(System.getProperty(prefix + "." + PROP_CRED_SOURCE));

        if (StringUtil.isEmpty(expectedIssuer)) {
            throw new IllegalStateException("Required property " + prefix + "." + PROP_ISSUER + " is not set");
        }
        if (StringUtil.isEmpty(expectedAudience)) {
            throw new IllegalStateException("Required property " + prefix + "." + PROP_AUDIENCE + " is not set");
        }
        if (StringUtil.isEmpty(certificateFile)) {
            throw new IllegalStateException("Required property " + prefix + "." + PROP_CERTIFICATE_FILE + " is not set");
        }

        try {
            trustedCertificates = Crypto.loadX509Certificates(certificateFile);
        } catch (CryptoException ex) {
            throw new IllegalStateException("Unable to load SAML signing certificate file: " + certificateFile, ex);
        }
        if (trustedCertificates == null || trustedCertificates.length == 0) {
            throw new IllegalStateException("SAML signing certificate file contains no certificates: " + certificateFile);
        }
    }

    @Override
    public String getID() {
        return AUTHORITY_ID;
    }

    @Override
    public CredSource getCredSource() {
        return credSource;
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
        return "SAML realm=\"athenz\"";
    }

    @Override
    public Principal authenticate(HttpServletRequest request, StringBuilder errMsg) {
        errMsg = errMsg == null ? new StringBuilder(512) : errMsg;
        if (request == null) {
            errMsg.append("SAMLAuthority:authenticate: request is null");
            return null;
        }

        String samlMessage = null;
        if (credSource == CredSource.REQUEST) {
            samlMessage = request.getParameter(requestParameter);
        } else {
            samlMessage = request.getHeader(headerName);
        }
        return authenticate(samlMessage, request.getRemoteAddr(), request.getMethod(), errMsg);
    }

    @Override
    public Principal authenticate(String creds, String remoteAddr, String httpMethod, StringBuilder errMsg) {
        errMsg = errMsg == null ? new StringBuilder(512) : errMsg;

        if (StringUtil.isEmpty(creds)) {
            errMsg.append("SAMLAuthority:authenticate: credentials are empty");
            return null;
        }
        if (creds.length() > maxMessageSizeBytes) {
            errMsg.append("SAMLAuthority:authenticate: credentials exceed maximum configured size");
            return null;
        }

        final Document document;
        try {
            document = parseSamlDocument(decodeSamlMessage(creds));
        } catch (Exception ex) {
            errMsg.append("SAMLAuthority:authenticate: unable to parse SAML message: ").append(ex.getMessage());
            return null;
        }
        if (!registerIdAttributes(document.getDocumentElement(), new HashSet<>())) {
            errMsg.append("SAMLAuthority:authenticate: SAML message contains duplicate ID values");
            return null;
        }

        final Element root = document.getDocumentElement();
        final Element responseElement;
        final Element assertionElement;
        if (isElement(root, SAML_PROTOCOL_NS, "Response")) {
            responseElement = root;
            if (!validateResponseStatus(responseElement, errMsg)) {
                return null;
            }
            if (!validateResponseDestination(responseElement, errMsg)) {
                return null;
            }
            final List<Element> assertions = getDirectChildElements(responseElement, SAML_ASSERTION_NS, "Assertion");
            if (assertions.size() != 1) {
                errMsg.append("SAMLAuthority:authenticate: expected exactly one assertion, found ")
                        .append(assertions.size());
                return null;
            }
            assertionElement = assertions.get(0);
        } else if (isElement(root, SAML_ASSERTION_NS, "Assertion")) {
            responseElement = null;
            assertionElement = root;
        } else {
            errMsg.append("SAMLAuthority:authenticate: unsupported SAML root element: ")
                    .append(root.getNodeName());
            return null;
        }

        if (!validateSignature(responseElement, assertionElement, errMsg)) {
            return null;
        }
        if (!validateIssuer(responseElement, assertionElement, errMsg)) {
            return null;
        }
        if (!validateConditions(assertionElement, errMsg)) {
            return null;
        }
        if (!validateAssertionLifetime(assertionElement, errMsg)) {
            return null;
        }
        if (!validateSubjectConfirmation(assertionElement, errMsg)) {
            return null;
        }

        final String principalName = extractPrincipalName(assertionElement, errMsg);
        if (principalName == null) {
            return null;
        }

        final long issueTime = parseIssueTimeSeconds(assertionElement);
        final String normalizedPrincipalName = principalName.toLowerCase(Locale.ROOT);
        if (!principalPattern.matcher(normalizedPrincipalName).matches()) {
            errMsg.append("SAMLAuthority:authenticate: invalid principal name: ").append(principalName);
            return null;
        }
        if (!checkAndRecordReplay(assertionElement, errMsg)) {
            return null;
        }
        final SimplePrincipal principal = getSimplePrincipal(normalizedPrincipalName, creds, issueTime);
        if (principal == null) {
            errMsg.append("SAMLAuthority:authenticate: failed to create principal: user=")
                    .append(principalName);
            LOG.error(errMsg.toString());
            return null;
        }
        principal.setUnsignedCreds(principalName);
        return principal;
    }

    SimplePrincipal getSimplePrincipal(String name, String creds, long issueTime) {
        return (SimplePrincipal) SimplePrincipal.create(getDomain(), name, creds, issueTime, this);
    }

    CredSource parseCredSource(final String configuredCredSource) {
        if (StringUtil.isEmpty(configuredCredSource)) {
            return CredSource.HEADER;
        }
        try {
            return CredSource.valueOf(configuredCredSource.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            LOG.warn("Invalid SAML credential source configured: {}, using default: {}",
                    configuredCredSource, CredSource.HEADER);
            return CredSource.HEADER;
        }
    }

    long parseClockSkewSeconds(final String configuredClockSkew) {
        if (StringUtil.isEmpty(configuredClockSkew)) {
            return DEFAULT_CLOCK_SKEW_SECONDS;
        }
        try {
            return Long.parseLong(configuredClockSkew);
        } catch (NumberFormatException ex) {
            LOG.warn("Invalid SAML clock skew configured: {}, using default: {}",
                    configuredClockSkew, DEFAULT_CLOCK_SKEW_SECONDS);
            return DEFAULT_CLOCK_SKEW_SECONDS;
        }
    }

    long parseLong(final String configuredValue, final long defaultValue, final String propertyName) {
        if (StringUtil.isEmpty(configuredValue)) {
            return defaultValue;
        }
        try {
            return Long.parseLong(configuredValue);
        } catch (NumberFormatException ex) {
            LOG.warn("Invalid SAML {} configured: {}, using default: {}",
                    propertyName, configuredValue, defaultValue);
            return defaultValue;
        }
    }

    int parsePositiveInt(final String configuredValue, final int defaultValue, final String propertyName) {
        if (StringUtil.isEmpty(configuredValue)) {
            return defaultValue;
        }
        try {
            final int value = Integer.parseInt(configuredValue);
            if (value > 0) {
                return value;
            }
        } catch (NumberFormatException ignored) {
        }
        LOG.warn("Invalid SAML {} configured: {}, using default: {}",
                propertyName, configuredValue, defaultValue);
        return defaultValue;
    }

    Pattern parsePrincipalPattern(final String configuredPattern, final String prefix) {
        try {
            return Pattern.compile(configuredPattern);
        } catch (PatternSyntaxException ex) {
            throw new IllegalStateException("Invalid regex for " + prefix + "." + PROP_PRINCIPAL_PATTERN
                    + ": " + configuredPattern + " (" + ex.getDescription() + ")", ex);
        }
    }

    static Set<String> parseCsvSet(final String configuredValue) {
        final Set<String> values = new HashSet<>();
        if (StringUtil.isEmpty(configuredValue)) {
            return values;
        }
        for (String value : configuredValue.split(",")) {
            final String trimmedValue = value.trim();
            if (!trimmedValue.isEmpty()) {
                values.add(trimmedValue);
            }
        }
        return values;
    }

    byte[] decodeSamlMessage(final String creds) throws IOException {
        String value = creds.trim();
        if (value.startsWith("SAML ")) {
            value = value.substring("SAML ".length()).trim();
        } else if (value.startsWith("SAMLResponse=")) {
            value = value.substring("SAMLResponse=".length()).trim();
        } else if (value.startsWith("SAMLAssertion=")) {
            value = value.substring("SAMLAssertion=".length()).trim();
        }
        if (value.startsWith("<")) {
            return value.getBytes(StandardCharsets.UTF_8);
        }

        final byte[] decoded = Base64.getMimeDecoder().decode(value);
        if (decoded.length > maxMessageSizeBytes) {
            throw new IOException("decoded SAML message exceeds maximum configured size");
        }
        if (startsWithXml(decoded)) {
            return decoded;
        }
        return inflate(decoded);
    }

    boolean startsWithXml(final byte[] data) {
        for (byte b : data) {
            if (Character.isWhitespace((char) b)) {
                continue;
            }
            return b == '<';
        }
        return false;
    }

    byte[] inflate(final byte[] data) throws IOException {
        try (InflaterInputStream inflater = new InflaterInputStream(new ByteArrayInputStream(data), new Inflater(true));
             ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = inflater.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
                if (outputStream.size() > maxMessageSizeBytes) {
                    throw new IOException("inflated SAML message exceeds maximum configured size");
                }
            }
            return outputStream.toByteArray();
        }
    }

    Document parseSamlDocument(final byte[] samlDocumentBytes)
            throws ParserConfigurationException, IOException, SAXException {

        final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);

        return factory.newDocumentBuilder().parse(new InputSource(new ByteArrayInputStream(samlDocumentBytes)));
    }

    boolean registerIdAttributes(final Element element, final Set<String> idValues) {
        if (element == null) {
            return true;
        }
        if (!registerIdAttribute(element, "ID", idValues) ||
                !registerIdAttribute(element, "Id", idValues) ||
                !registerIdAttribute(element, "id", idValues)) {
            return false;
        }

        final NodeList children = element.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            final Node child = children.item(i);
            if (child instanceof Element && !registerIdAttributes((Element) child, idValues)) {
                return false;
            }
        }
        return true;
    }

    boolean registerIdAttribute(final Element element, final String attributeName, final Set<String> idValues) {
        if (!element.hasAttribute(attributeName)) {
            return true;
        }
        final String idValue = element.getAttribute(attributeName);
        if (StringUtil.isEmpty(idValue) || !idValues.add(idValue)) {
            return false;
        }
        element.setIdAttribute(attributeName, true);
        return true;
    }

    boolean validateResponseStatus(final Element responseElement, final StringBuilder errMsg) {
        final Element status = getFirstDirectChildElement(responseElement, SAML_PROTOCOL_NS, "Status");
        final Element statusCode = getFirstDirectChildElement(status, SAML_PROTOCOL_NS, "StatusCode");
        final String statusValue = statusCode == null ? null : statusCode.getAttribute("Value");
        if (!SAML_SUCCESS_STATUS.equals(statusValue)) {
            errMsg.append("SAMLAuthority:authenticate: SAML response status is not success: ")
                    .append(statusValue);
            return false;
        }
        return true;
    }

    boolean validateResponseDestination(final Element responseElement, final StringBuilder errMsg) {
        if (StringUtil.isEmpty(expectedRecipient)) {
            return true;
        }
        final String destination = responseElement.getAttribute("Destination");
        if (!StringUtil.isEmpty(destination) && !expectedRecipient.equals(destination)) {
            errMsg.append("SAMLAuthority:authenticate: response destination does not match expected recipient");
            return false;
        }
        return true;
    }

    boolean validateSignature(final Element responseElement, final Element assertionElement, final StringBuilder errMsg) {

        if (hasDirectSignature(assertionElement) && validateElementSignature(assertionElement, errMsg)) {
            return true;
        }
        if (responseElement != null && hasDirectSignature(responseElement) &&
                validateElementSignature(responseElement, errMsg)) {
            return true;
        }

        errMsg.append("SAMLAuthority:authenticate: SAML assertion or response signature is not valid");
        return false;
    }

    boolean hasDirectSignature(final Element signedElement) {
        return getFirstDirectChildElement(signedElement, XML_SIGNATURE_NS, "Signature") != null;
    }

    boolean validateElementSignature(final Element signedElement, final StringBuilder errMsg) {

        final Element signatureElement = getFirstDirectChildElement(signedElement, XML_SIGNATURE_NS, "Signature");
        if (signatureElement == null) {
            return false;
        }

        final XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
        for (X509Certificate certificate : trustedCertificates) {
            try {
                certificate.checkValidity();
                final DOMValidateContext validationContext =
                        new DOMValidateContext(certificate.getPublicKey(), signatureElement);
                validationContext.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.TRUE);
                final XMLSignature signature = signatureFactory.unmarshalXMLSignature(validationContext);
                if (!isAllowedSignatureAlgorithm(signature) ||
                        !signatureOnlyReferencesSignedElement(signature, signedElement)) {
                    continue;
                }
                if (signature.validate(validationContext)) {
                    return true;
                }
            } catch (CertificateExpiredException | CertificateNotYetValidException |
                     XMLSignatureException | RuntimeException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("SAML signature validation failed for certificate subject={}: {}",
                            certificate.getSubjectX500Principal(), ex.getMessage());
                }
            } catch (Exception ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("SAML signature validation failed for certificate subject={}: {}",
                            certificate.getSubjectX500Principal(), ex.getMessage());
                }
            }
        }
        return false;
    }

    boolean isAllowedSignatureAlgorithm(final XMLSignature signature) {
        if (!allowedSignatureAlgorithms.contains(signature.getSignedInfo().getSignatureMethod().getAlgorithm())) {
            return false;
        }
        for (Object referenceObject : signature.getSignedInfo().getReferences()) {
            final Reference reference = (Reference) referenceObject;
            if (!allowedDigestAlgorithms.contains(reference.getDigestMethod().getAlgorithm())) {
                return false;
            }
        }
        return true;
    }

    boolean signatureOnlyReferencesSignedElement(final XMLSignature signature, final Element signedElement) {
        final String id = signedElement.getAttribute("ID");
        if (StringUtil.isEmpty(id)) {
            return false;
        }
        final List<?> references = signature.getSignedInfo().getReferences();
        if (references.size() != 1) {
            return false;
        }
        final String expectedUri = "#" + id;
        final Reference reference = (Reference) references.get(0);
        return expectedUri.equals(reference.getURI());
    }

    boolean validateIssuer(final Element responseElement, final Element assertionElement, final StringBuilder errMsg) {
        final String assertionIssuer = getDirectChildText(assertionElement, SAML_ASSERTION_NS, "Issuer");
        if (!expectedIssuer.equals(assertionIssuer)) {
            errMsg.append("SAMLAuthority:authenticate: assertion issuer is not the configured issuer: ")
                    .append(assertionIssuer);
            return false;
        }

        if (responseElement != null) {
            final String responseIssuer = getDirectChildText(responseElement, SAML_ASSERTION_NS, "Issuer");
            if (!StringUtil.isEmpty(responseIssuer) && !expectedIssuer.equals(responseIssuer)) {
                errMsg.append("SAMLAuthority:authenticate: response issuer is not the configured issuer: ")
                        .append(responseIssuer);
                return false;
            }
        }
        return true;
    }

    boolean validateConditions(final Element assertionElement, final StringBuilder errMsg) {

        final Element conditions = getFirstDirectChildElement(assertionElement, SAML_ASSERTION_NS, "Conditions");
        if (conditions == null) {
            errMsg.append("SAMLAuthority:authenticate: assertion does not contain Conditions");
            return false;
        }

        if (!validateNotBefore(conditions.getAttribute("NotBefore"), errMsg)) {
            return false;
        }
        if (!validateNotOnOrAfter(conditions.getAttribute("NotOnOrAfter"), "conditions", errMsg)) {
            return false;
        }

        final List<String> audiences = extractAudiences(conditions);
        if (!audiences.contains(expectedAudience)) {
            errMsg.append("SAMLAuthority:authenticate: assertion audience does not contain expected audience: ")
                    .append(expectedAudience);
            return false;
        }
        return true;
    }

    boolean validateAssertionLifetime(final Element assertionElement, final StringBuilder errMsg) {
        if (maxAssertionTtlSeconds <= 0) {
            return true;
        }

        final String issueInstantValue = assertionElement.getAttribute("IssueInstant");
        if (StringUtil.isEmpty(issueInstantValue)) {
            errMsg.append("SAMLAuthority:authenticate: assertion does not contain IssueInstant");
            return false;
        }
        final Instant issueInstant = parseSamlDateTime(issueInstantValue, errMsg);
        if (issueInstant == null) {
            return false;
        }
        if (issueInstant.isAfter(Instant.now().plusSeconds(clockSkewSeconds))) {
            errMsg.append("SAMLAuthority:authenticate: assertion IssueInstant is in the future: ")
                    .append(issueInstantValue);
            return false;
        }

        final Instant notOnOrAfter = extractConditionsNotOnOrAfter(assertionElement, errMsg);
        if (notOnOrAfter == null) {
            return false;
        }
        if (!notOnOrAfter.isAfter(issueInstant)) {
            errMsg.append("SAMLAuthority:authenticate: assertion NotOnOrAfter is not after IssueInstant");
            return false;
        }
        if (Duration.between(issueInstant, notOnOrAfter).getSeconds() > maxAssertionTtlSeconds) {
            errMsg.append("SAMLAuthority:authenticate: assertion lifetime exceeds maximum configured TTL");
            return false;
        }
        return true;
    }

    Instant extractConditionsNotOnOrAfter(final Element assertionElement, final StringBuilder errMsg) {
        final Element conditions = getFirstDirectChildElement(assertionElement, SAML_ASSERTION_NS, "Conditions");
        if (conditions == null) {
            errMsg.append("SAMLAuthority:authenticate: assertion does not contain Conditions");
            return null;
        }
        final String notOnOrAfter = conditions.getAttribute("NotOnOrAfter");
        if (StringUtil.isEmpty(notOnOrAfter)) {
            errMsg.append("SAMLAuthority:authenticate: assertion conditions does not contain NotOnOrAfter");
            return null;
        }
        return parseSamlDateTime(notOnOrAfter, errMsg);
    }

    boolean checkAndRecordReplay(final Element assertionElement, final StringBuilder errMsg) {
        if (!replayCacheEnabled) {
            return true;
        }

        final String assertionId = assertionElement.getAttribute("ID");
        if (StringUtil.isEmpty(assertionId)) {
            errMsg.append("SAMLAuthority:authenticate: assertion does not contain ID");
            return false;
        }

        final Instant expiry = extractConditionsNotOnOrAfter(assertionElement, errMsg);
        if (expiry == null) {
            return false;
        }
        final long now = System.currentTimeMillis();
        cleanupReplayCache(now);
        if (replayCache.size() >= replayCacheMaxEntries) {
            errMsg.append("SAMLAuthority:authenticate: replay cache is full");
            return false;
        }

        final long replayExpiresAt = expiry.plusSeconds(clockSkewSeconds).toEpochMilli();
        final Long existingExpiry = replayCache.putIfAbsent(assertionId, replayExpiresAt);
        if (existingExpiry == null) {
            return true;
        }
        if (existingExpiry > now) {
            errMsg.append("SAMLAuthority:authenticate: assertion replay detected");
            return false;
        }
        if (!replayCache.replace(assertionId, existingExpiry, replayExpiresAt)) {
            errMsg.append("SAMLAuthority:authenticate: assertion replay cache update failed");
            return false;
        }
        return true;
    }

    void cleanupReplayCache(final long now) {
        replayCache.entrySet().removeIf(entry -> entry.getValue() <= now);
    }

    boolean validateSubjectConfirmation(final Element assertionElement, final StringBuilder errMsg) {

        final Element subject = getFirstDirectChildElement(assertionElement, SAML_ASSERTION_NS, "Subject");
        final List<Element> confirmations = getDirectChildElements(subject, SAML_ASSERTION_NS, "SubjectConfirmation");
        StringBuilder lastValidationError = new StringBuilder();
        for (Element confirmation : confirmations) {
            final String method = confirmation.getAttribute("Method");
            if (!SAML_BEARER_METHOD.equals(method)) {
                continue;
            }
            final Element confirmationData = getFirstDirectChildElement(
                    confirmation, SAML_ASSERTION_NS, "SubjectConfirmationData");
            if (confirmationData == null) {
                continue;
            }
            lastValidationError = new StringBuilder();
            if (!validateNotOnOrAfter(confirmationData.getAttribute("NotOnOrAfter"),
                    "subject confirmation", lastValidationError)) {
                continue;
            }
            if (!StringUtil.isEmpty(expectedRecipient) &&
                    !expectedRecipient.equals(confirmationData.getAttribute("Recipient"))) {
                lastValidationError.setLength(0);
                lastValidationError.append("SAMLAuthority:authenticate: subject confirmation recipient does not match expected recipient");
                continue;
            }
            return true;
        }

        if (lastValidationError.length() > 0) {
            errMsg.append(lastValidationError);
        } else {
            errMsg.append("SAMLAuthority:authenticate: assertion does not contain a valid bearer subject confirmation");
        }
        return false;
    }

    boolean validateNotBefore(final String notBefore, final StringBuilder errMsg) {
        if (StringUtil.isEmpty(notBefore)) {
            return true;
        }
        final Instant notBeforeInstant = parseSamlDateTime(notBefore, errMsg);
        if (notBeforeInstant == null) {
            return false;
        }
        if (Instant.now().plusSeconds(clockSkewSeconds).isBefore(notBeforeInstant)) {
            errMsg.append("SAMLAuthority:authenticate: assertion is not valid before: ").append(notBefore);
            return false;
        }
        return true;
    }

    boolean validateNotOnOrAfter(final String notOnOrAfter, final String fieldName, final StringBuilder errMsg) {
        if (StringUtil.isEmpty(notOnOrAfter)) {
            errMsg.append("SAMLAuthority:authenticate: assertion ").append(fieldName)
                    .append(" does not contain NotOnOrAfter");
            return false;
        }
        final Instant notOnOrAfterInstant = parseSamlDateTime(notOnOrAfter, errMsg);
        if (notOnOrAfterInstant == null) {
            return false;
        }
        if (!Instant.now().minusSeconds(clockSkewSeconds).isBefore(notOnOrAfterInstant)) {
            errMsg.append("SAMLAuthority:authenticate: assertion ").append(fieldName)
                    .append(" is expired: ").append(notOnOrAfter);
            return false;
        }
        return true;
    }

    Instant parseSamlDateTime(final String dateTime, final StringBuilder errMsg) {
        try {
            return Instant.parse(dateTime);
        } catch (DateTimeException ignored) {
            try {
                return OffsetDateTime.parse(dateTime).toInstant();
            } catch (DateTimeException ex) {
                errMsg.append("SAMLAuthority:authenticate: invalid SAML dateTime: ").append(dateTime);
                return null;
            }
        }
    }

    List<String> extractAudiences(final Element conditions) {
        final List<String> audiences = new ArrayList<>();
        for (Element audienceRestriction : getDirectChildElements(conditions, SAML_ASSERTION_NS, "AudienceRestriction")) {
            for (Element audience : getDirectChildElements(audienceRestriction, SAML_ASSERTION_NS, "Audience")) {
                final String value = textContent(audience);
                if (!StringUtil.isEmpty(value)) {
                    audiences.add(value);
                }
            }
        }
        return audiences;
    }

    String extractPrincipalName(final Element assertionElement, final StringBuilder errMsg) {
        final String principalName = StringUtil.isEmpty(principalNameAttribute) ?
                extractNameId(assertionElement, errMsg) : extractAttributeValue(assertionElement, principalNameAttribute);
        if (StringUtil.isEmpty(principalName)) {
            errMsg.append("SAMLAuthority:authenticate: assertion does not contain principal name");
            return null;
        }
        return principalName;
    }

    String extractNameId(final Element assertionElement, final StringBuilder errMsg) {
        final Element subject = getFirstDirectChildElement(assertionElement, SAML_ASSERTION_NS, "Subject");
        final Element nameId = getFirstDirectChildElement(subject, SAML_ASSERTION_NS, "NameID");
        if (nameId == null) {
            return null;
        }
        if (!StringUtil.isEmpty(expectedNameIdFormat) &&
                !expectedNameIdFormat.equals(nameId.getAttribute("Format"))) {
            errMsg.append("SAMLAuthority:authenticate: NameID format does not match expected format");
            return null;
        }
        return textContent(nameId);
    }

    String extractAttributeValue(final Element assertionElement, final String attributeName) {
        for (Element attributeStatement : getDirectChildElements(assertionElement, SAML_ASSERTION_NS, "AttributeStatement")) {
            for (Element attribute : getDirectChildElements(attributeStatement, SAML_ASSERTION_NS, "Attribute")) {
                if (!attributeName.equals(attribute.getAttribute("Name")) &&
                        !attributeName.equals(attribute.getAttribute("FriendlyName"))) {
                    continue;
                }
                final Element value = getFirstDirectChildElement(attribute, SAML_ASSERTION_NS, "AttributeValue");
                if (value != null) {
                    return textContent(value);
                }
            }
        }
        return null;
    }

    long parseIssueTimeSeconds(final Element assertionElement) {
        final String issueInstant = assertionElement.getAttribute("IssueInstant");
        if (StringUtil.isEmpty(issueInstant)) {
            return 0;
        }
        try {
            return Instant.parse(issueInstant).getEpochSecond();
        } catch (DateTimeException ex) {
            try {
                return OffsetDateTime.parse(issueInstant).toInstant().getEpochSecond();
            } catch (DateTimeException ignored) {
                return 0;
            }
        }
    }

    String getDirectChildText(final Element parent, final String namespace, final String localName) {
        final Element child = getFirstDirectChildElement(parent, namespace, localName);
        return child == null ? null : textContent(child);
    }

    Element getFirstDirectChildElement(final Element parent, final String namespace, final String localName) {
        final List<Element> elements = getDirectChildElements(parent, namespace, localName);
        return elements.isEmpty() ? null : elements.get(0);
    }

    List<Element> getDirectChildElements(final Element parent, final String namespace, final String localName) {
        final List<Element> elements = new ArrayList<>();
        if (parent == null) {
            return elements;
        }
        final NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            final Node child = children.item(i);
            if (child instanceof Element && isElement((Element) child, namespace, localName)) {
                elements.add((Element) child);
            }
        }
        return elements;
    }

    boolean isElement(final Element element, final String namespace, final String localName) {
        return namespace.equals(element.getNamespaceURI()) && localName.equals(element.getLocalName());
    }

    String textContent(final Element element) {
        return element == null ? null : element.getTextContent().trim();
    }
}
