package com.yahoo.athenz.auth.impl;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.assertTrue;

public class SPIFFECertificateAuthorityTest {

    private static final String TRUST_DOMAIN = "spire.example";

    @AfterMethod
    public void clearProperties() {
        System.clearProperty(SPIFFECertificateAuthority.PROP_AUTHORIZED_TRUST_DOMAINS);
        System.clearProperty(SPIFFECertificateAuthority.PROP_ALLOW_GLOBAL_SPIFFE_ID);
        System.clearProperty(SPIFFECertificateAuthority.PROP_NAMESPACE_AS_DOMAIN);
        System.clearProperty(SPIFFECertificateAuthority.PROP_EXCLUDED_PRINCIPALS);
        System.clearProperty("athenz.auth.certificate.excluded_principals");
    }

    @Test
    public void authenticatesAthenzTrustDomainUri() throws Exception {
        System.setProperty(SPIFFECertificateAuthority.PROP_AUTHORIZED_TRUST_DOMAINS,
                " other.example, SPIRE.EXAMPLE ");
        SPIFFECertificateAuthority authority = authority();
        X509Certificate cert = certificate("",
                "spiffe://spire.example/ns/prod/sa/Team.Payments.Api",
                "athenz://hostname/host.example");

        Principal principal = authority.authenticate(new X509Certificate[]{cert}, new StringBuilder());

        assertNotNull(principal);
        assertEquals(principal.getFullName(), "team.payments.api");
        assertEquals(principal.getDomain(), "team.payments");
        assertEquals(principal.getName(), "api");
        assertSame(principal.getAuthority(), authority);
        assertSame(principal.getX509Certificate(), cert);
        assertEquals(principal.getUnsignedCredentials(), "team.payments.api");
        assertFalse(principal.getMtlsRestricted());
        assertEquals(authority.getCredSource(), Authority.CredSource.CERTIFICATE);
        assertEquals(authority.getID(), "Auth-SPIFFE-X509");
        assertEquals(authority.getAuthenticateChallenge(), "AthenzX509Certificate realm=\"spiffe\"");
        assertNull(authority.getHeader());
        assertNull(authority.getDomain());
        assertNull(authority.authenticate("ignored", null, null, new StringBuilder()));
    }

    @Test
    public void originalNamespaceAsDomainFormatRequiresOptIn() throws Exception {
        System.setProperty(SPIFFECertificateAuthority.PROP_AUTHORIZED_TRUST_DOMAINS, TRUST_DOMAIN);
        X509Certificate cert = certificate("O=Example Workload",
                "spiffe://spire.example/ns/team.payments/sa/api");
        assertNull(authority().authenticate(new X509Certificate[]{cert}, new StringBuilder()));

        System.setProperty(SPIFFECertificateAuthority.PROP_NAMESPACE_AS_DOMAIN, "true");
        Principal principal = authority().authenticate(new X509Certificate[]{cert}, new StringBuilder());
        assertNotNull(principal);
        assertEquals(principal.getFullName(), "team.payments.api");
    }

    @Test
    public void basicAthenzUriRequiresOptIn() throws Exception {
        X509Certificate cert = certificate("O=Example Workload", "spiffe://team.payments/sa/api");
        SPIFFECertificateAuthority authority = authority();
        assertNull(authority.authenticate(new X509Certificate[]{cert}, new StringBuilder()));

        System.setProperty(SPIFFECertificateAuthority.PROP_ALLOW_GLOBAL_SPIFFE_ID, "true");
        authority.initialize();
        Principal principal = authority.authenticate(new X509Certificate[]{cert}, new StringBuilder());
        assertNotNull(principal);
        assertEquals(principal.getFullName(), "team.payments.api");

        System.clearProperty(SPIFFECertificateAuthority.PROP_ALLOW_GLOBAL_SPIFFE_ID);
        authority.initialize();
        assertNull(authority.authenticate(new X509Certificate[]{cert}, new StringBuilder()));
    }

    @Test
    public void rejectsExcludedPrincipals() throws Exception {
        System.setProperty(SPIFFECertificateAuthority.PROP_AUTHORIZED_TRUST_DOMAINS, TRUST_DOMAIN);
        System.setProperty(SPIFFECertificateAuthority.PROP_EXCLUDED_PRINCIPALS, " TEAM.PAYMENTS.API ");
        X509Certificate cert = certificate("O=Example Workload",
                "spiffe://spire.example/ns/prod/sa/team.payments.api");
        StringBuilder error = new StringBuilder();

        assertNull(authority().authenticate(new X509Certificate[]{cert}, error));
        assertTrue(error.toString().contains("Principal is excluded"));

        System.clearProperty(SPIFFECertificateAuthority.PROP_EXCLUDED_PRINCIPALS);
        System.setProperty("athenz.auth.certificate.excluded_principals", "team.payments.api");
        assertNull(authority().authenticate(new X509Certificate[]{cert}, new StringBuilder()));
    }

    @Test
    public void filtersIssuerUsingAthenzTruststore() throws Exception {
        System.setProperty(SPIFFECertificateAuthority.PROP_AUTHORIZED_TRUST_DOMAINS, TRUST_DOMAIN);
        Path bundle = Files.createTempFile("spiffe-ca-", ".pem");
        String previousPath = System.getProperty("athenz.authority.truststore.path");
        try {
            X509Certificate ca = selfSignedCa();
            String pem = "-----BEGIN CERTIFICATE-----\n"
                    + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(ca.getEncoded())
                    + "\n-----END CERTIFICATE-----\n";
            Files.writeString(bundle, pem);
            System.setProperty("athenz.authority.truststore.path", bundle.toString());
            SPIFFECertificateAuthority authority = authority();
            X509Certificate workload = certificate("",
                    "spiffe://spire.example/ns/prod/sa/team.payments.api");

            assertNull(authority.authenticate(new X509Certificate[]{workload}, new StringBuilder()));
            when(workload.getIssuerX500Principal()).thenReturn(new X500Principal("CN=Allowed CA"));
            assertNotNull(authority.authenticate(new X509Certificate[]{workload}, new StringBuilder()));
        } finally {
            if (previousPath == null) {
                System.clearProperty("athenz.authority.truststore.path");
            } else {
                System.setProperty("athenz.authority.truststore.path", previousPath);
            }
            Files.deleteIfExists(bundle);
        }
    }

    @Test
    public void rejectsMissingOrAmbiguousCertificateIdentity() throws Exception {
        System.setProperty(SPIFFECertificateAuthority.PROP_AUTHORIZED_TRUST_DOMAINS, TRUST_DOMAIN);
        SPIFFECertificateAuthority authority = authority();
        assertNull(authority.authenticate((X509Certificate[]) null, new StringBuilder()));
        assertNull(authority.authenticate(new X509Certificate[0], new StringBuilder()));
        assertNull(authority.authenticate(new X509Certificate[]{null}, new StringBuilder()));
        assertNull(authority.authenticate(new X509Certificate[]{certificate("O=Example Workload")},
                new StringBuilder()));
        assertNull(authority.authenticate(new X509Certificate[]{certificate("CN=team.payments.api",
                "spiffe://spire.example/ns/prod/sa/team.payments.api")}, new StringBuilder()));
        assertNull(authority.authenticate(new X509Certificate[]{certificate("CN=one,CN=two",
                "spiffe://spire.example/ns/prod/sa/team.payments.api")}, new StringBuilder()));
        assertNull(authority.authenticate(new X509Certificate[]{certificate("OU=one,OU=two",
                "spiffe://spire.example/ns/prod/sa/team.payments.api")}, new StringBuilder()));
        assertNull(authority.authenticate(new X509Certificate[]{certificate("O=Example Workload",
                "spiffe://spire.example/ns/prod/sa/team.payments.api",
                "spiffe://other.example/ns/prod/sa/other.api")}, new StringBuilder()));
    }

    @DataProvider
    public Object[][] invalidSpiffeIds() {
        return new Object[][]{
                {"spiffe://other.example/ns/prod/sa/team.api"},
                {"spiffe://spire.example/ns/prod/ra/team.readers"},
                {"spiffe://spire.example/ns/prod/sa/team.api/"},
                {"spiffe://spire.example/ns/prod/sa/team..api"},
                {"spiffe://spire.example/ns/prod/sa/team.api?name=other"},
                {"spiffe://spire.example/ns/prod/sa/team.api#other"},
                {"spiffe://spire.example/ns/prod/sa/team%2Eapi"},
                {"spiffe://spire.example:8443/ns/prod/sa/team.api"},
                {"spiffe://user@spire.example/ns/prod/sa/team.api"},
                {"spiffe:spire.example/ns/prod/sa/team.api"},
                {"spiffe://spire.example/ns/prod/sa/team:role"},
        };
    }

    @Test(dataProvider = "invalidSpiffeIds")
    public void rejectsInvalidSpiffeId(String uri) throws Exception {
        System.setProperty(SPIFFECertificateAuthority.PROP_AUTHORIZED_TRUST_DOMAINS, TRUST_DOMAIN);
        X509Certificate cert = certificate("O=Example Workload", uri);
        StringBuilder error = new StringBuilder();

        assertNull(authority().authenticate(new X509Certificate[]{cert}, error));
        assertTrue(error.toString().contains("Invalid or unauthorized SPIFFE ID"));
    }

    private static SPIFFECertificateAuthority authority() {
        SPIFFECertificateAuthority authority = new SPIFFECertificateAuthority();
        authority.initialize();
        return authority;
    }

    private static X509Certificate certificate(String subject, String... uris) throws Exception {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getSubjectX500Principal()).thenReturn(new X500Principal(subject));
        when(cert.getIssuerX500Principal()).thenReturn(new X500Principal("CN=Example CA"));
        Collection<List<?>> sanEntries = new ArrayList<>();
        for (String uri : uris) {
            sanEntries.add(List.of(6, uri));
        }
        when(cert.getSubjectAlternativeNames()).thenReturn(sanEntries);
        return cert;
    }

    private static X509Certificate selfSignedCa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keys = generator.generateKeyPair();
        X500Name name = new X500Name("CN=Allowed CA");
        long now = System.currentTimeMillis();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, BigInteger.ONE,
                new Date(now - 60_000), new Date(now + 60_000), name, keys.getPublic());
        return new JcaX509CertificateConverter().getCertificate(builder.build(
                new JcaContentSignerBuilder("SHA256withRSA").build(keys.getPrivate())));
    }
}
