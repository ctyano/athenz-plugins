package com.yahoo.athenz.auth.impl;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.util.Crypto;
import jakarta.servlet.http.HttpServletRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

public class SAMLAuthorityTest {

    private static final String ISSUER = "https://idp.example/saml";
    private static final String AUDIENCE = "https://athenz.example/zms";
    private static final String RECIPIENT = "https://athenz.example/saml/acs";
    private final List<Path> tempFiles = new ArrayList<>();

    @AfterMethod
    public void clearProperties() throws Exception {
        final String prefix = SAMLAuthority.DEFAULT_PROPERTY_PREFIX;
        System.clearProperty(prefix + "." + SAMLAuthority.PROP_HEADER);
        System.clearProperty(prefix + "." + SAMLAuthority.PROP_CRED_SOURCE);
        System.clearProperty(prefix + "." + SAMLAuthority.PROP_REQUEST_PARAMETER);
        System.clearProperty(prefix + "." + SAMLAuthority.PROP_DOMAIN);
        System.clearProperty(prefix + "." + SAMLAuthority.PROP_ISSUER);
        System.clearProperty(prefix + "." + SAMLAuthority.PROP_AUDIENCE);
        System.clearProperty(prefix + "." + SAMLAuthority.PROP_CERTIFICATE_FILE);
        System.clearProperty(prefix + "." + SAMLAuthority.PROP_NAME_ATTRIBUTE);
        System.clearProperty(prefix + "." + SAMLAuthority.PROP_NAME_ID_FORMAT);
        System.clearProperty(prefix + "." + SAMLAuthority.PROP_RECIPIENT);
        System.clearProperty(prefix + "." + SAMLAuthority.PROP_CLOCK_SKEW);

        for (Path tempFile : tempFiles) {
            Files.deleteIfExists(tempFile);
        }
        tempFiles.clear();
    }

    @Test
    public void testGetters() {
        SAMLAuthority authority = new SAMLAuthority();
        assertEquals(authority.getID(), "Auth-SAML");
        assertEquals(authority.getDomain(), "user");
        assertEquals(authority.getHeader(), "X-SAML-Assertion");
        assertEquals(authority.getCredSource(), Authority.CredSource.HEADER);
        assertEquals(authority.getAuthenticateChallenge(), "SAML realm=\"athenz\"");
    }

    @Test
    public void testAuthenticateSignedAssertion() throws Exception {
        TestSamlContext context = setupAuthority();

        String encodedResponse = encode(buildSignedResponse(context, "Athenz-Admin",
                Instant.now().minusSeconds(30), Instant.now().plusSeconds(300),
                AUDIENCE, ISSUER, true, null, null));

        StringBuilder errMsg = new StringBuilder();
        Principal principal = context.authority.authenticate(encodedResponse, "127.0.0.1", "POST", errMsg);

        assertNotNull(principal);
        assertEquals(principal.getDomain(), "user");
        assertEquals(principal.getName(), "athenz-admin");
        assertEquals(errMsg.toString(), "");
    }

    @Test
    public void testAuthenticateSignedResponse() throws Exception {
        TestSamlContext context = setupAuthority();

        String encodedResponse = encode(buildSignedResponse(context, "athenz-admin",
                Instant.now().minusSeconds(30), Instant.now().plusSeconds(300),
                AUDIENCE, ISSUER, false, null, null));

        Principal principal = context.authority.authenticate(encodedResponse, "127.0.0.1", "POST",
                new StringBuilder());

        assertNotNull(principal);
        assertEquals(principal.getName(), "athenz-admin");
    }

    @Test
    public void testAuthenticateRequestParameter() throws Exception {
        final String prefix = SAMLAuthority.DEFAULT_PROPERTY_PREFIX;
        System.setProperty(prefix + "." + SAMLAuthority.PROP_CRED_SOURCE, "REQUEST");
        TestSamlContext context = setupAuthority();

        String encodedResponse = encode(buildSignedResponse(context, "athenz-admin",
                Instant.now().minusSeconds(30), Instant.now().plusSeconds(300),
                AUDIENCE, ISSUER, true, null, null));

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getParameter(SAMLAuthority.DEFAULT_REQUEST_PARAMETER)).thenReturn(encodedResponse);
        Mockito.when(request.getRemoteAddr()).thenReturn("127.0.0.1");
        Mockito.when(request.getMethod()).thenReturn("POST");

        Principal principal = context.authority.authenticate(request, new StringBuilder());

        assertEquals(context.authority.getCredSource(), Authority.CredSource.REQUEST);
        assertNotNull(principal);
        assertEquals(principal.getName(), "athenz-admin");
    }

    @Test
    public void testAuthenticateAttributePrincipal() throws Exception {
        final String prefix = SAMLAuthority.DEFAULT_PROPERTY_PREFIX;
        System.setProperty(prefix + "." + SAMLAuthority.PROP_NAME_ATTRIBUTE, "email");
        TestSamlContext context = setupAuthority();

        String encodedResponse = encode(buildSignedResponse(context, "ignored-user",
                Instant.now().minusSeconds(30), Instant.now().plusSeconds(300),
                AUDIENCE, ISSUER, true, "email", "Athenz-Admin@example.com"));

        Principal principal = context.authority.authenticate(encodedResponse, "127.0.0.1", "POST",
                new StringBuilder());

        assertNotNull(principal);
        assertEquals(principal.getName(), "athenz-admin@example.com");
    }

    @Test
    public void testAuthenticateRejectsTamperedAssertion() throws Exception {
        TestSamlContext context = setupAuthority();

        String signedResponse = buildSignedResponse(context, "athenz-admin",
                Instant.now().minusSeconds(30), Instant.now().plusSeconds(300),
                AUDIENCE, ISSUER, true, null, null);
        String tamperedResponse = signedResponse.replace("athenz-admin", "other-user");

        StringBuilder errMsg = new StringBuilder();
        Principal principal = context.authority.authenticate(encode(tamperedResponse),
                "127.0.0.1", "POST", errMsg);

        assertNull(principal);
        assertTrue(errMsg.toString().contains("signature is not valid"), errMsg.toString());
    }

    @Test
    public void testAuthenticateRejectsAudienceMismatch() throws Exception {
        TestSamlContext context = setupAuthority();

        String encodedResponse = encode(buildSignedResponse(context, "athenz-admin",
                Instant.now().minusSeconds(30), Instant.now().plusSeconds(300),
                "https://other.example/zms", ISSUER, true, null, null));

        StringBuilder errMsg = new StringBuilder();
        Principal principal = context.authority.authenticate(encodedResponse, "127.0.0.1", "POST", errMsg);

        assertNull(principal);
        assertTrue(errMsg.toString().contains("audience"), errMsg.toString());
    }

    @Test
    public void testAuthenticateRejectsExpiredAssertion() throws Exception {
        TestSamlContext context = setupAuthority();

        String encodedResponse = encode(buildSignedResponse(context, "athenz-admin",
                Instant.now().minusSeconds(600), Instant.now().minusSeconds(300),
                AUDIENCE, ISSUER, true, null, null));

        StringBuilder errMsg = new StringBuilder();
        Principal principal = context.authority.authenticate(encodedResponse, "127.0.0.1", "POST", errMsg);

        assertNull(principal);
        assertTrue(errMsg.toString().contains("expired"), errMsg.toString());
    }

    private TestSamlContext setupAuthority() throws Exception {
        KeyPair keyPair = generateKeyPair();
        X509Certificate certificate = generateCertificate(keyPair);
        Path certificateFile = Files.createTempFile("saml-signing-cert", ".pem");
        tempFiles.add(certificateFile);
        Files.writeString(certificateFile, Crypto.x509CertificatesToPEM(new X509Certificate[]{certificate}));

        final String prefix = SAMLAuthority.DEFAULT_PROPERTY_PREFIX;
        System.setProperty(prefix + "." + SAMLAuthority.PROP_ISSUER, ISSUER);
        System.setProperty(prefix + "." + SAMLAuthority.PROP_AUDIENCE, AUDIENCE);
        System.setProperty(prefix + "." + SAMLAuthority.PROP_CERTIFICATE_FILE, certificateFile.toString());
        System.setProperty(prefix + "." + SAMLAuthority.PROP_RECIPIENT, RECIPIENT);

        SAMLAuthority authority = new SAMLAuthority();
        authority.initialize();
        return new TestSamlContext(authority, keyPair, certificate);
    }

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private X509Certificate generateCertificate(KeyPair keyPair) throws Exception {
        X500Name subject = new X500Name("CN=saml-test");
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(subject,
                BigInteger.valueOf(now.toEpochMilli()), Date.from(now.minusSeconds(60)),
                Date.from(now.plusSeconds(3600)), subject, keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    private String buildSignedResponse(TestSamlContext context, String nameId, Instant notBefore,
            Instant notOnOrAfter, String audience, String issuer, boolean signAssertion,
            String attributeName, String attributeValue) throws Exception {

        final String responseId = "_" + UUID.randomUUID().toString().replace("-", "");
        final String assertionId = "_" + UUID.randomUUID().toString().replace("-", "");
        final String issueInstant = Instant.now().toString();
        final String attributeStatement = attributeName == null ? "" :
                "<saml:AttributeStatement>" +
                        "<saml:Attribute Name=\"" + attributeName + "\">" +
                        "<saml:AttributeValue>" + attributeValue + "</saml:AttributeValue>" +
                        "</saml:Attribute>" +
                        "</saml:AttributeStatement>";

        String xml = "<samlp:Response xmlns:samlp=\"" + SAMLAuthority.SAML_PROTOCOL_NS + "\" " +
                "xmlns:saml=\"" + SAMLAuthority.SAML_ASSERTION_NS + "\" " +
                "ID=\"" + responseId + "\" Version=\"2.0\" IssueInstant=\"" + issueInstant + "\">" +
                "<saml:Issuer>" + issuer + "</saml:Issuer>" +
                "<samlp:Status><samlp:StatusCode Value=\"" + SAMLAuthority.SAML_SUCCESS_STATUS + "\"/>" +
                "</samlp:Status>" +
                "<saml:Assertion ID=\"" + assertionId + "\" Version=\"2.0\" IssueInstant=\"" + issueInstant + "\">" +
                "<saml:Issuer>" + issuer + "</saml:Issuer>" +
                "<saml:Subject>" +
                "<saml:NameID>" + nameId + "</saml:NameID>" +
                "<saml:SubjectConfirmation Method=\"" + SAMLAuthority.SAML_BEARER_METHOD + "\">" +
                "<saml:SubjectConfirmationData Recipient=\"" + RECIPIENT + "\" NotOnOrAfter=\"" +
                notOnOrAfter + "\"/>" +
                "</saml:SubjectConfirmation>" +
                "</saml:Subject>" +
                "<saml:Conditions NotBefore=\"" + notBefore + "\" NotOnOrAfter=\"" + notOnOrAfter + "\">" +
                "<saml:AudienceRestriction><saml:Audience>" + audience + "</saml:Audience></saml:AudienceRestriction>" +
                "</saml:Conditions>" +
                attributeStatement +
                "</saml:Assertion>" +
                "</samlp:Response>";

        Document document = parseXml(xml);
        Element elementToSign = signAssertion ?
                (Element) document.getElementsByTagNameNS(SAMLAuthority.SAML_ASSERTION_NS, "Assertion").item(0) :
                document.getDocumentElement();
        signElement(context, elementToSign);
        return serialize(document);
    }

    private void signElement(TestSamlContext context, Element elementToSign) throws Exception {
        elementToSign.setIdAttribute("ID", true);
        String referenceId = "#" + elementToSign.getAttribute("ID");

        XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
        Reference reference = signatureFactory.newReference(referenceId,
                signatureFactory.newDigestMethod(DigestMethod.SHA256, null),
                Collections.singletonList(signatureFactory.newTransform(
                        Transform.ENVELOPED, (TransformParameterSpec) null)),
                null, null);
        SignedInfo signedInfo = signatureFactory.newSignedInfo(
                signatureFactory.newCanonicalizationMethod(
                        CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
                signatureFactory.newSignatureMethod(SignatureMethod.RSA_SHA256, null),
                Collections.singletonList(reference));

        KeyInfoFactory keyInfoFactory = signatureFactory.getKeyInfoFactory();
        X509Data x509Data = keyInfoFactory.newX509Data(Collections.singletonList(context.certificate));
        KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(x509Data));

        DOMSignContext signContext = new DOMSignContext(context.keyPair.getPrivate(), elementToSign);
        signContext.setDefaultNamespacePrefix("ds");
        signatureFactory.newXMLSignature(signedInfo, keyInfo).sign(signContext);
    }

    private Document parseXml(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        return factory.newDocumentBuilder().parse(
                new java.io.ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }

    private String serialize(Document document) throws Exception {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(document), new StreamResult(writer));
        return writer.toString();
    }

    private String encode(String xml) {
        return Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8));
    }

    private static class TestSamlContext {
        final SAMLAuthority authority;
        final KeyPair keyPair;
        final X509Certificate certificate;

        TestSamlContext(SAMLAuthority authority, KeyPair keyPair, X509Certificate certificate) {
            this.authority = authority;
            this.keyPair = keyPair;
            this.certificate = certificate;
        }
    }
}
