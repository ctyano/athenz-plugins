package com.yahoo.athenz.instance.provider.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.yahoo.athenz.auth.TokenExchangeIdentityProvider;
import com.yahoo.athenz.auth.token.OAuth2Token;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.server.db.RolesProvider;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ProviderResourceException;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMember;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

public class InstanceLocalAgentProviderTest {

    private static final String ISSUER = "https://okta.example.test/oauth2/default";
    private static final String OTHER_ISSUER = "https://dex.example.test";
    private static final String AUDIENCE = "athenz-local-agent";

    private final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");
    private final ClassLoader classLoader = this.getClass().getClassLoader();

    @AfterMethod
    public void clearProperties() {
        System.clearProperty(InstanceLocalAgentProvider.LOCAL_AGENT_PROP_ISSUER);
        System.clearProperty(InstanceLocalAgentProvider.LOCAL_AGENT_PROP_JWKS_URI);
        System.clearProperty(InstanceLocalAgentProvider.LOCAL_AGENT_PROP_JWKS_URI_MAP);
        System.clearProperty(InstanceLocalAgentProvider.LOCAL_AGENT_PROP_AUDIENCE);
        System.clearProperty(InstanceLocalAgentProvider.LOCAL_AGENT_PROP_USER_NAME_CLAIM);
        System.clearProperty(InstanceLocalAgentProvider.LOCAL_AGENT_PROP_USER_NAME_CLAIMS);
        System.clearProperty(InstanceLocalAgentProvider.LOCAL_AGENT_PROP_USER_DOMAIN_TEMPLATE);
        System.clearProperty(InstanceLocalAgentProvider.LOCAL_AGENT_PROP_EXTERNAL_MEMBER_CLAIMS);
        System.clearProperty(InstanceLocalAgentProvider.LOCAL_AGENT_PROP_EXTERNAL_MEMBER_TEMPLATE);
        System.clearProperty(InstanceLocalAgentProvider.LOCAL_AGENT_PROP_EXTERNAL_IDENTITY_PROVIDER_CLASS);
        System.clearProperty(InstanceLocalAgentProvider.LOCAL_AGENT_PROP_BOOT_TIME_OFFSET);
    }

    @Test
    public void testConfirmInstanceWithDiscoveredJwksAndUserHomeDomain() throws Exception {
        configureAudience();

        TestProvider provider = newProvider();
        provider.discoveryJwksUri = jwksUri();

        InstanceConfirmation confirmation = newConfirmation("home.alice.agent", "proxy",
                "Bearer " + generateToken(ISSUER, AUDIENCE, Map.of("athenz_user", "user.Alice")));

        InstanceConfirmation result = provider.confirmInstance(confirmation);

        assertNotNull(result);
        assertEquals(result.getAttributes().get(InstanceProvider.ZTS_CERT_REFRESH), "false");
        assertEquals(result.getAttributes().get(InstanceProvider.ZTS_CERT_USAGE), "client");
        assertEquals(provider.lastDiscoveryIssuer, ISSUER);
    }

    @Test
    public void testConfirmInstanceWithFallbackJwksAndExternalAdminMember() throws Exception {
        configureAudience();
        System.setProperty(InstanceLocalAgentProvider.LOCAL_AGENT_PROP_JWKS_URI, jwksUri());
        System.setProperty(InstanceLocalAgentProvider.LOCAL_AGENT_PROP_USER_NAME_CLAIM, "athenz_user");
        System.setProperty(InstanceLocalAgentProvider.LOCAL_AGENT_PROP_EXTERNAL_MEMBER_CLAIMS, "email");

        TestProvider provider = newProvider();
        provider.setRolesProvider(new TestRolesProvider()
                .addMembership("home.alice.agent", "developer@example.com", "admin"));

        InstanceConfirmation confirmation = newConfirmation("home.alice.agent", "proxy",
                generateToken(OTHER_ISSUER, AUDIENCE, Map.of(
                        "athenz_user", "bob",
                        "email", "Developer@Example.COM")));

        InstanceConfirmation result = provider.confirmInstance(confirmation);

        assertNotNull(result);
        assertEquals(result.getAttributes().get(InstanceProvider.ZTS_CERT_REFRESH), "false");
    }

    @Test
    public void testConfirmInstanceWithExternalMemberTemplate() throws Exception {
        configureAudience();
        System.setProperty(InstanceLocalAgentProvider.LOCAL_AGENT_PROP_JWKS_URI, jwksUri());
        System.setProperty(InstanceLocalAgentProvider.LOCAL_AGENT_PROP_EXTERNAL_MEMBER_CLAIMS, "email");
        System.setProperty(InstanceLocalAgentProvider.LOCAL_AGENT_PROP_EXTERNAL_MEMBER_TEMPLATE, "email:ext.%s");

        TestProvider provider = newProvider();
        provider.setRolesProvider(new TestRolesProvider()
                .addMembership("home.alice.agent", "email:ext.developer@example.com", "admin"));

        InstanceConfirmation confirmation = newConfirmation("home.alice.agent", "proxy",
                generateToken(OTHER_ISSUER, AUDIENCE, Map.of(
                        "athenz_user", "bob",
                        "email", "developer@example.com")));

        InstanceConfirmation result = provider.confirmInstance(confirmation);

        assertNotNull(result);
    }

    @Test
    public void testConfirmInstanceWithExternalIdentityProviderClass() throws Exception {
        configureAudience();
        System.setProperty(InstanceLocalAgentProvider.LOCAL_AGENT_PROP_JWKS_URI, jwksUri());
        System.setProperty(InstanceLocalAgentProvider.LOCAL_AGENT_PROP_EXTERNAL_MEMBER_CLAIMS, "");
        System.setProperty(InstanceLocalAgentProvider.LOCAL_AGENT_PROP_EXTERNAL_IDENTITY_PROVIDER_CLASS,
                TestExternalIdentityProvider.class.getName());

        TestProvider provider = newProvider();
        provider.setRolesProvider(new TestRolesProvider()
                .addMembership("home.alice.agent", "email:ext.developer@example.com", "admin"));

        InstanceConfirmation confirmation = newConfirmation("home.alice.agent", "proxy",
                generateToken(OTHER_ISSUER, AUDIENCE, Map.of(
                        "athenz_user", "bob",
                        "email", "Developer@Example.COM")));

        InstanceConfirmation result = provider.confirmInstance(confirmation);

        assertNotNull(result);
    }

    @Test
    public void testConfirmInstanceRejectsWrongDomainWithoutAdminMembership() throws Exception {
        configureAudience();
        System.setProperty(InstanceLocalAgentProvider.LOCAL_AGENT_PROP_JWKS_URI, jwksUri());
        System.setProperty(InstanceLocalAgentProvider.LOCAL_AGENT_PROP_EXTERNAL_MEMBER_CLAIMS, "email");

        TestProvider provider = newProvider();
        provider.setRolesProvider(new TestRolesProvider());

        InstanceConfirmation confirmation = newConfirmation("home.alice.agent", "proxy",
                generateToken(ISSUER, AUDIENCE, Map.of(
                        "athenz_user", "bob",
                        "email", "developer@example.com")));

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("not authorized"));
        }
    }

    @Test
    public void testConfirmInstanceRejectsIssuerOutsideAllowlist() throws Exception {
        configureAudience();
        System.setProperty(InstanceLocalAgentProvider.LOCAL_AGENT_PROP_ISSUER, ISSUER);
        System.setProperty(InstanceLocalAgentProvider.LOCAL_AGENT_PROP_JWKS_URI, jwksUri());

        TestProvider provider = newProvider();

        InstanceConfirmation confirmation = newConfirmation("home.alice", "proxy",
                generateToken(OTHER_ISSUER, AUDIENCE, Map.of("athenz_user", "alice")));

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("issuer is not configured"));
        }
    }

    @Test
    public void testConfirmInstanceRejectsInvalidAudience() throws Exception {
        configureAudience();
        System.setProperty(InstanceLocalAgentProvider.LOCAL_AGENT_PROP_JWKS_URI, jwksUri());

        TestProvider provider = newProvider();
        InstanceConfirmation confirmation = newConfirmation("home.alice", "proxy",
                generateToken(ISSUER, "other-audience", Map.of("athenz_user", "alice")));

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Token audience is not configured"));
        }
    }

    @Test
    public void testInitializeRequiresAudience() {
        try {
            newProvider();
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("audience must be configured"));
        }
    }

    @Test
    public void testRefreshInstanceForbidden() {
        TestProvider provider = new TestProvider();

        try {
            provider.refreshInstance(new InstanceConfirmation());
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("cannot be refreshed"));
        }
    }

    @Test
    public void testDirectAdminRoleFallback() throws Exception {
        configureAudience();
        System.setProperty(InstanceLocalAgentProvider.LOCAL_AGENT_PROP_JWKS_URI, jwksUri());
        System.setProperty(InstanceLocalAgentProvider.LOCAL_AGENT_PROP_EXTERNAL_MEMBER_CLAIMS, "email");

        TestProvider provider = newProvider();
        provider.setRolesProvider(new TestRolesProvider()
                .setUseRolesForPrincipal(false)
                .addRole("home.alice.agent", new Role()
                        .setName("home.alice.agent:role.admin")
                        .setRoleMembers(List.of(new RoleMember().setMemberName("developer@example.com")))));

        InstanceConfirmation confirmation = newConfirmation("home.alice.agent", "proxy",
                generateToken(ISSUER, AUDIENCE, Map.of(
                        "athenz_user", "bob",
                        "email", "developer@example.com")));

        InstanceConfirmation result = provider.confirmInstance(confirmation);

        assertNotNull(result);
    }

    private void configureAudience() {
        System.setProperty(InstanceLocalAgentProvider.LOCAL_AGENT_PROP_AUDIENCE, AUDIENCE);
    }

    private TestProvider newProvider() {
        TestProvider provider = new TestProvider();
        provider.initialize("sys.auth.local-agent",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceLocalAgentProvider", null, null);
        return provider;
    }

    private InstanceConfirmation newConfirmation(final String domain, final String service,
            final String attestationData) {
        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setProvider("sys.auth.local-agent");
        confirmation.setDomain(domain);
        confirmation.setService(service);
        confirmation.setAttestationData(attestationData);
        return confirmation;
    }

    private String generateToken(final String issuer, final String audience, final Map<String, Object> claims)
            throws JOSEException {
        final long currentTimeSecs = System.currentTimeMillis() / 1000;
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        ECDSASigner signer = new ECDSASigner((ECPrivateKey) privateKey);
        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(audience)
                .subject("id-token")
                .issueTime(Date.from(Instant.ofEpochSecond(currentTimeSecs)))
                .expirationTime(Date.from(Instant.ofEpochSecond(currentTimeSecs + 3600)));

        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            claimsSetBuilder.claim(entry.getKey(), entry.getValue());
        }

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("eckey1").build(),
                claimsSetBuilder.build());
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }

    private String jwksUri() {
        return Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
    }

    private static final class TestProvider extends InstanceLocalAgentProvider {

        String discoveryJwksUri;
        String lastDiscoveryIssuer;

        @Override
        String extractIssuerJwksUri(final String issuer) {
            lastDiscoveryIssuer = issuer;
            return discoveryJwksUri;
        }
    }

    private static final class TestRolesProvider implements RolesProvider {

        private final Map<String, Map<String, Set<String>>> memberships = new HashMap<>();
        private final Map<String, List<Role>> rolesByDomain = new HashMap<>();
        private boolean useRolesForPrincipal = true;

        TestRolesProvider addMembership(final String domain, final String member, final String role) {
            memberships.computeIfAbsent(domain, key -> new HashMap<>()).put(member, Set.of(role));
            return this;
        }

        TestRolesProvider addRole(final String domain, final Role role) {
            rolesByDomain.put(domain, List.of(role));
            return this;
        }

        TestRolesProvider setUseRolesForPrincipal(final boolean useRolesForPrincipal) {
            this.useRolesForPrincipal = useRolesForPrincipal;
            return this;
        }

        @Override
        public Set<String> getRolesForPrincipal(final String domainName, final String principal) {
            if (!useRolesForPrincipal) {
                throw new UnsupportedOperationException();
            }
            return memberships.getOrDefault(domainName, Collections.emptyMap())
                    .getOrDefault(principal, Collections.emptySet());
        }

        @Override
        public List<Role> getRolesByDomain(final String domainName) {
            return rolesByDomain.getOrDefault(domainName, Collections.emptyList());
        }
    }

    public static final class TestExternalIdentityProvider implements TokenExchangeIdentityProvider {

        @Override
        public String getTokenIdentity(final OAuth2Token token) {
            final Object emailClaim = token.getClaim("email");
            if (emailClaim == null) {
                return null;
            }
            final String email = emailClaim.toString().trim().toLowerCase(Locale.ROOT);
            return email.isEmpty() ? null : "email:ext." + email;
        }

        @Override
        public String getTokenAudience(final OAuth2Token token) {
            return token == null ? null : token.getAudience();
        }

        @Override
        public List<String> getTokenExchangeClaims() {
            return Collections.singletonList("email");
        }
    }
}
