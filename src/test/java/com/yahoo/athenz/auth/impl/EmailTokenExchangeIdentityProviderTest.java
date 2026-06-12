package com.yahoo.athenz.auth.impl;

import com.yahoo.athenz.auth.token.OAuth2Token;
import org.testng.annotations.Test;

import java.util.Collections;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

public class EmailTokenExchangeIdentityProviderTest {

    @Test
    public void testGetTokenIdentityMapsEmailClaim() {
        OAuth2Token token = new TestOAuth2Token("audience", Map.of("email", " Athenz_User@ATHENZ.IO "));

        EmailTokenExchangeIdentityProvider provider = new EmailTokenExchangeIdentityProvider();

        assertEquals(provider.getTokenIdentity(token), "email:ext.athenz_user@athenz.io");
    }

    @Test
    public void testGetTokenIdentityReturnsNullWithoutEmailClaim() {
        OAuth2Token token = new TestOAuth2Token("audience", Collections.emptyMap());

        EmailTokenExchangeIdentityProvider provider = new EmailTokenExchangeIdentityProvider();

        assertNull(provider.getTokenIdentity(token));
    }

    @Test
    public void testGetTokenIdentityReturnsNullWithBlankEmailClaim() {
        OAuth2Token token = new TestOAuth2Token("audience", Map.of("email", "  "));

        EmailTokenExchangeIdentityProvider provider = new EmailTokenExchangeIdentityProvider();

        assertNull(provider.getTokenIdentity(token));
    }

    @Test
    public void testGetTokenAudienceReturnsTokenAudience() {
        OAuth2Token token = new TestOAuth2Token("email.subdomain", Collections.emptyMap());

        EmailTokenExchangeIdentityProvider provider = new EmailTokenExchangeIdentityProvider();

        assertEquals(provider.getTokenAudience(token), "email.subdomain");
    }

    @Test
    public void testGetTokenExchangeClaimsReturnsEmailClaim() {
        EmailTokenExchangeIdentityProvider provider = new EmailTokenExchangeIdentityProvider();

        assertEquals(provider.getTokenExchangeClaims(), Collections.singletonList("email"));
    }

    private static class TestOAuth2Token extends OAuth2Token {

        private final String audience;
        private final Map<String, Object> claims;

        TestOAuth2Token(final String audience, final Map<String, Object> claims) {
            this.audience = audience;
            this.claims = claims;
        }

        @Override
        public String getAudience() {
            return audience;
        }

        @Override
        public Object getClaim(final String name) {
            return claims.get(name);
        }
    }
}
