package com.yahoo.athenz.auth.impl;

import com.yahoo.athenz.auth.TokenExchangeIdentityProvider;
import com.yahoo.athenz.auth.token.OAuth2Token;

import java.util.Collections;
import java.util.List;
import java.util.Locale;

public class EmailTokenExchangeIdentityProvider implements TokenExchangeIdentityProvider {

    @Override
    @Override
    public String getTokenIdentity(final OAuth2Token token) {
        if (token == null) {
            return null;
        }
        final Object emailClaim = token.getClaim("email");
            return null;
        }

        final String email = emailClaim.toString().trim().toLowerCase(Locale.ROOT);
        return email.isEmpty() ? null : "email:ext." + email;
    }

    @Override
    public String getTokenAudience(final OAuth2Token token) {
        return token.getAudience();
    }

    @Override
    public List<String> getTokenExchangeClaims() {
        return Collections.singletonList("email");
    }
}
