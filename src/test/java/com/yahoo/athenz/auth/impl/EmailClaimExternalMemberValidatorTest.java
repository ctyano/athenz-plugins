package com.yahoo.athenz.auth.impl;

import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class EmailClaimExternalMemberValidatorTest {

    @AfterMethod
    public void clearProperties() {
        System.clearProperty(EmailClaimExternalMemberValidator.ATHENZ_PROP_EMAIL_ALLOWED_DOMAINS);
        System.clearProperty(EmailClaimExternalMemberValidator.ATHENZ_PROP_EMAIL_ALLOWED_DOMAINS_PREFIX + "sports");
        System.clearProperty(EmailClaimExternalMemberValidator.ATHENZ_PROP_EMAIL_ALLOWED_DOMAINS_PREFIX + "finance");
    }

    @Test
    public void testValidateMemberWithExactAllowedDomain() {
        System.setProperty(EmailClaimExternalMemberValidator.ATHENZ_PROP_EMAIL_ALLOWED_DOMAINS,
                "example.com, example.org");

        EmailClaimExternalMemberValidator validator = new EmailClaimExternalMemberValidator();

        assertTrue(validator.validateMember("sports", "alice@example.com"));
        assertTrue(validator.validateMember("sports", "Alice+Role@Example.ORG"));
        assertFalse(validator.validateMember("sports", "alice@example.net"));
        assertFalse(validator.validateMember("sports", "alice@example.com.evil"));
    }

    @Test
    public void testValidateMemberWithDomainSpecificAllowedDomains() {
        System.setProperty(EmailClaimExternalMemberValidator.ATHENZ_PROP_EMAIL_ALLOWED_DOMAINS, "example.com");
        System.setProperty(EmailClaimExternalMemberValidator.ATHENZ_PROP_EMAIL_ALLOWED_DOMAINS_PREFIX + "sports",
                "sports.example");

        EmailClaimExternalMemberValidator validator = new EmailClaimExternalMemberValidator();

        assertTrue(validator.validateMember("sports", "alice@sports.example"));
        assertFalse(validator.validateMember("sports", "alice@example.com"));
        assertTrue(validator.validateMember("finance", "alice@example.com"));
    }

    @Test
    public void testValidateMemberWithWildcardSubdomain() {
        System.setProperty(EmailClaimExternalMemberValidator.ATHENZ_PROP_EMAIL_ALLOWED_DOMAINS,
                "example.com,*.example.net");

        EmailClaimExternalMemberValidator validator = new EmailClaimExternalMemberValidator();

        assertTrue(validator.validateMember("sports", "alice@example.com"));
        assertTrue(validator.validateMember("sports", "alice@dev.example.net"));
        assertFalse(validator.validateMember("sports", "alice@example.net"));
        assertFalse(validator.validateMember("sports", "alice@badexample.net"));
    }

    @Test
    public void testValidateMemberFailsClosedWithoutAllowedDomains() {
        EmailClaimExternalMemberValidator validator = new EmailClaimExternalMemberValidator();

        assertFalse(validator.validateMember("sports", "alice@example.com"));
    }

    @Test
    public void testValidateMemberRejectsInvalidEmailAddresses() {
        System.setProperty(EmailClaimExternalMemberValidator.ATHENZ_PROP_EMAIL_ALLOWED_DOMAINS, "example.com");

        EmailClaimExternalMemberValidator validator = new EmailClaimExternalMemberValidator();

        assertFalse(validator.validateMember("sports", null));
        assertFalse(validator.validateMember("sports", ""));
        assertFalse(validator.validateMember("sports", "alice"));
        assertFalse(validator.validateMember("sports", "alice@@example.com"));
        assertFalse(validator.validateMember("sports", "alice @example.com"));
        assertFalse(validator.validateMember("sports", ".alice@example.com"));
        assertFalse(validator.validateMember("sports", "alice.@example.com"));
        assertFalse(validator.validateMember("sports", "alice..role@example.com"));
        assertFalse(validator.validateMember("sports", "\"alice\"@example.com"));
        assertFalse(validator.validateMember("sports", "alice@example..com"));
        assertFalse(validator.validateMember("sports", "alice@-example.com"));
        assertFalse(validator.validateMember("sports", "alice@example.com."));
    }

    @Test
    public void testValidateMemberWithIdnDomain() {
        System.setProperty(EmailClaimExternalMemberValidator.ATHENZ_PROP_EMAIL_ALLOWED_DOMAINS,
                "xn--bcher-kva.example");

        EmailClaimExternalMemberValidator validator = new EmailClaimExternalMemberValidator();

        assertTrue(validator.validateMember("sports", "alice@bücher.example"));
    }
}
