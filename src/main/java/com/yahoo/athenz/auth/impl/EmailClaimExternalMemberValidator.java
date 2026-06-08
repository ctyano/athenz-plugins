package com.yahoo.athenz.auth.impl;

import com.yahoo.athenz.auth.ExternalMemberValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.IDN;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class EmailClaimExternalMemberValidator implements ExternalMemberValidator {

    private static final Logger LOG = LoggerFactory.getLogger(EmailClaimExternalMemberValidator.class);

    public static final String ATHENZ_PROP_EMAIL_ALLOWED_DOMAINS =
            "athenz.auth.external_member.email.allowed_domains";
    public static final String ATHENZ_PROP_EMAIL_ALLOWED_DOMAINS_PREFIX =
            ATHENZ_PROP_EMAIL_ALLOWED_DOMAINS + ".";

    private static final int MAX_EMAIL_LENGTH = 254;
    private static final int MAX_LOCAL_PART_LENGTH = 64;
    private static final int MAX_DOMAIN_LENGTH = 253;
    private static final int MAX_DOMAIN_LABEL_LENGTH = 63;

    private final AllowedEmailDomains defaultAllowedDomains;
    private final ConcurrentMap<String, AllowedEmailDomains> domainAllowedDomains = new ConcurrentHashMap<>();

    public EmailClaimExternalMemberValidator() {
        defaultAllowedDomains = parseAllowedEmailDomains(System.getProperty(ATHENZ_PROP_EMAIL_ALLOWED_DOMAINS));
    }

    @Override
    public boolean validateMember(final String domainName, final String memberName) {
        final String emailDomain = extractEmailDomain(memberName);
        if (emailDomain == null) {
            return false;
        }
        return getAllowedEmailDomains(domainName).contains(emailDomain);
    }

    AllowedEmailDomains getAllowedEmailDomains(final String domainName) {
        if (isEmpty(domainName)) {
            return defaultAllowedDomains;
        }
        return domainAllowedDomains.computeIfAbsent(domainName, this::loadAllowedEmailDomains);
    }

    AllowedEmailDomains loadAllowedEmailDomains(final String domainName) {
        final String propertyValue = System.getProperty(ATHENZ_PROP_EMAIL_ALLOWED_DOMAINS_PREFIX + domainName);
        if (isEmpty(propertyValue)) {
            return defaultAllowedDomains;
        }
        return parseAllowedEmailDomains(propertyValue);
    }

    AllowedEmailDomains parseAllowedEmailDomains(final String propertyValue) {
        if (isEmpty(propertyValue)) {
            return AllowedEmailDomains.EMPTY;
        }

        final Set<String> exactDomains = new HashSet<>();
        final Set<String> suffixDomains = new HashSet<>();
        for (String value : propertyValue.split(",")) {
            final String token = value.trim();
            if (token.isEmpty()) {
                continue;
            }

            final boolean suffixMatch = token.startsWith("*.");
            final String domain = normalizeDomain(suffixMatch ? token.substring(2) : token);
            if (domain == null) {
                LOG.warn("Ignoring invalid allowed email domain: {}", token);
                continue;
            }

            if (suffixMatch) {
                suffixDomains.add(domain);
            } else {
                exactDomains.add(domain);
            }
        }
        return new AllowedEmailDomains(exactDomains, suffixDomains);
    }

    String extractEmailDomain(final String email) {
        if (isEmpty(email) || email.length() > MAX_EMAIL_LENGTH) {
            return null;
        }

        final int atIndex = email.indexOf('@');
        if (atIndex <= 0 || atIndex != email.lastIndexOf('@') || atIndex == email.length() - 1) {
            return null;
        }

        if (!isValidLocalPart(email.substring(0, atIndex))) {
            return null;
        }
        return normalizeDomain(email.substring(atIndex + 1));
    }

    boolean isValidLocalPart(final String localPart) {
        if (localPart.isEmpty() || localPart.length() > MAX_LOCAL_PART_LENGTH ||
                localPart.charAt(0) == '.' || localPart.charAt(localPart.length() - 1) == '.') {
            return false;
        }

        boolean previousDot = false;
        for (int idx = 0; idx < localPart.length(); idx++) {
            final char ch = localPart.charAt(idx);
            if (!isAllowedLocalPartChar(ch)) {
                return false;
            }
            if (ch == '.') {
                if (previousDot) {
                    return false;
                }
                previousDot = true;
            } else {
                previousDot = false;
            }
        }
        return true;
    }

    boolean isAllowedLocalPartChar(final char ch) {
        return ch >= 'A' && ch <= 'Z' ||
                ch >= 'a' && ch <= 'z' ||
                ch >= '0' && ch <= '9' ||
                ch == '!' || ch == '#' || ch == '$' || ch == '%' || ch == '&' ||
                ch == '\'' || ch == '*' || ch == '+' || ch == '-' || ch == '/' ||
                ch == '=' || ch == '?' || ch == '^' || ch == '_' || ch == '`' ||
                ch == '{' || ch == '|' || ch == '}' || ch == '~' || ch == '.';
    }

    String normalizeDomain(final String domain) {
        if (isEmpty(domain) || domain.length() > MAX_DOMAIN_LENGTH ||
                domain.charAt(0) == '.' || domain.charAt(domain.length() - 1) == '.') {
            return null;
        }

        final String asciiDomain = toAsciiDomain(domain);

        if (asciiDomain.isEmpty() || asciiDomain.length() > MAX_DOMAIN_LENGTH) {
            return null;
        }

        int labelStart = 0;
        for (int idx = 0; idx <= asciiDomain.length(); idx++) {
            if (idx != asciiDomain.length() && asciiDomain.charAt(idx) != '.') {
                continue;
            }
            if (!isValidDomainLabel(asciiDomain, labelStart, idx)) {
                return null;
            }
            labelStart = idx + 1;
        }
        return asciiDomain;
    }

    String toAsciiDomain(final String domain) {
        if (isAscii(domain)) {
            return domain.toLowerCase(Locale.ROOT);
        }
        try {
            return IDN.toASCII(domain, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException ex) {
            return "";
        }
    }

    boolean isAscii(final String value) {
        for (int idx = 0; idx < value.length(); idx++) {
            if (value.charAt(idx) > 0x7F) {
                return false;
            }
        }
        return true;
    }

    boolean isValidDomainLabel(final String domain, final int start, final int end) {
        final int length = end - start;
        if (length <= 0 || length > MAX_DOMAIN_LABEL_LENGTH ||
                domain.charAt(start) == '-' || domain.charAt(end - 1) == '-') {
            return false;
        }
        for (int idx = start; idx < end; idx++) {
            final char ch = domain.charAt(idx);
            if (!(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-')) {
                return false;
            }
        }
        return true;
    }

    static boolean isEmpty(final String value) {
        return value == null || value.isEmpty();
    }

    static final class AllowedEmailDomains {

        static final AllowedEmailDomains EMPTY = new AllowedEmailDomains(Collections.emptySet(), Collections.emptySet());

        private final Set<String> exactDomains;
        private final Set<String> suffixDomains;

        AllowedEmailDomains(final Set<String> exactDomains, final Set<String> suffixDomains) {
            this.exactDomains = Set.copyOf(exactDomains);
            this.suffixDomains = Set.copyOf(suffixDomains);
        }

        boolean contains(final String emailDomain) {
            if (exactDomains.contains(emailDomain)) {
                return true;
            }
            for (String suffixDomain : suffixDomains) {
                final int separatorIdx = emailDomain.length() - suffixDomain.length() - 1;
                if (separatorIdx > 0 && emailDomain.charAt(separatorIdx) == '.' &&
                        emailDomain.endsWith(suffixDomain)) {
                    return true;
                }
            }
            return false;
        }
    }
}
