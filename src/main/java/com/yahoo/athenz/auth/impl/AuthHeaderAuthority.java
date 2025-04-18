package com.yahoo.athenz.auth.impl;

import java.util.HashSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.util.matcher.IpAddressMatcher;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;

public class AuthHeaderAuthority implements Authority {

    private static final Logger LOG = LoggerFactory.getLogger(AuthHeaderAuthority.class);
    
    public static final String AUTH_HEADER_USER_DEFAULT = "X-Auth-User";
    public static final String ATHENZ_PROP_AUTH_HEADER_USER = "athenz.auth.principal.auth.header.user";
    
    public static final String AUTH_HEADER_TRUSTED_CIDR_DEFAULT = "127.0.0.1/32";
    public static final String ATHENZ_PROP_AUTH_HEADER_TRUSTED_CIDR = "athenz.auth.principal.auth.header.trusted_cidr";
    
    protected HashSet<String> trusted_cidrs = new HashSet<>(); 

    @Override
    public void initialize() {
        String[] trusted_cidrs_csv = System.getProperty(ATHENZ_PROP_AUTH_HEADER_TRUSTED_CIDR, AUTH_HEADER_TRUSTED_CIDR_DEFAULT).split(",");
        for (String cidr : trusted_cidrs_csv) {
        	trusted_cidrs.add(cidr.trim());
        }
    }

    @Override
    public String getID() {
        return "Auth-Header";
    }

    @Override
    public String getDomain() {
        return "user";
    }

    @Override
    public String getHeader() {
        return System.getProperty(ATHENZ_PROP_AUTH_HEADER_USER, AUTH_HEADER_USER_DEFAULT);
    }

    @Override
    public String getAuthenticateChallenge() {
        return null;
    }

    @Override
    public boolean allowAuthorization() {
        return true;
    }

    @Override
    public Principal authenticate(String username, String remoteAddr, String httpMethod, StringBuilder errMsg) {
        errMsg = errMsg == null ? new StringBuilder(512) : errMsg;

        if (LOG.isDebugEnabled()) {
            LOG.debug("AuthHeaderAuthority.authenticate: username={}", username);
        }
        
        if (username == null || username.isEmpty()) {
            LOG.warn("AuthorizedAuthHeaderAuthority.authenticate: invalid username={}", username);
        	return null;
        }

        if (!checkIpAddressMatch(remoteAddr)) {
            errMsg.append("AuthHeaderAuthority:authenticate: remote ip address is not trusted: ip=")
                .append(remoteAddr);
            LOG.error(errMsg.toString());
            return null;
        }

        long issueTime = 0;
        SimplePrincipal princ = getSimplePrincipal(username.toLowerCase(), username, issueTime);
        if (princ == null) {
            errMsg.append("AuthHeaderAuthority:authenticate: failed to create principal: user=")
                .append(username);
            LOG.error(errMsg.toString());
            return null;
        }
        princ.setUnsignedCreds(username);
        
        return princ;
    }

    SimplePrincipal getSimplePrincipal(String name, String creds, long issueTime) {
        return (SimplePrincipal) SimplePrincipal.create(getDomain(),
                name, creds, issueTime, this);
    }

    boolean checkIpAddressMatch(String remoteAddr) {
        for (String cidr : trusted_cidrs) {
        	try {
                IpAddressMatcher ipAddressMatcher = new IpAddressMatcher(cidr);
                if (ipAddressMatcher.matches(remoteAddr)) {
                    return true;
                }
			} catch (IllegalArgumentException e) {
	            LOG.warn("AuthHeaderAuthority.checkIpAddressMatch: invalid remoteAddr={} message={}", remoteAddr, e.getMessage());
			}
        }
		return false;
    }
}
