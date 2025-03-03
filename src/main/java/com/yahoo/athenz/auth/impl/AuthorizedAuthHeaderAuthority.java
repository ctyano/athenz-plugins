package com.yahoo.athenz.auth.impl;

import java.util.HashSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.util.matcher.IpAddressMatcher;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.common.server.util.ServletRequestUtil;

import jakarta.servlet.http.HttpServletRequest;

public class AuthorizedAuthHeaderAuthority implements Authority {

    private static final Logger LOG = LoggerFactory.getLogger(AuthorizedAuthHeaderAuthority.class);

    public static final String AUTH_HEADER_USER_DEFAULT = "X-Auth-User";
    public static final String ATHENZ_PROP_AUTH_HEADER_USER = "athenz.auth.principal.auth.header.user";
    public static final String AUTH_HEADER_AUTHORIZED_SERVICE_DEFAULT = "X-Auth-Authorized-Service";
    public static final String ATHENZ_PROP_AUTH_HEADER_AUTHORIZED_SERVICE = "athenz.auth.principal.auth.header.authorized_service";
    
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
        return "Authorized-Auth-Header";
    }
    
    @Override
    public CredSource getCredSource() {
        return CredSource.REQUEST;
    }

    @Override
    public String getDomain() {
        return "user";
    }

    @Override
    public String getHeader() {
        return System.getProperty(ATHENZ_PROP_AUTH_HEADER_USER, AUTH_HEADER_USER_DEFAULT);
    }

    public String getAuthorizedServiceHeader() {
        return System.getProperty(ATHENZ_PROP_AUTH_HEADER_AUTHORIZED_SERVICE, AUTH_HEADER_AUTHORIZED_SERVICE_DEFAULT);
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
	public Principal authenticate(String creds, String remoteAddr, String httpMethod, StringBuilder errMsg) {
		return null;
	}

    @Override
    public Principal authenticate(HttpServletRequest request, StringBuilder errMsg) {
        errMsg = errMsg == null ? new StringBuilder(512) : errMsg;

        String username = request.getHeader(this.getHeader());
        String authorizedServiceName = request.getHeader(this.getAuthorizedServiceHeader());
        
        if (username.isEmpty()) {
            errMsg.append("AuthorizedAuthHeaderAuthority.authenticate: invalid user=").append(username)
                .append(" authorized service=").append(authorizedServiceName);
            LOG.error(errMsg.toString());
        	return null;
        }
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("AuthorizedAuthHeaderAuthority.authenticate: valid user={} authorized service={}", username, authorizedServiceName);
        }

        String remoteAddr = ServletRequestUtil.getRemoteAddress(request);
        if (!checkIpAddressMatch(remoteAddr)) {
            errMsg.append("AuthorizedAuthHeaderAuthority:authenticate: remote ip address is not trusted: ip=")
                .append(remoteAddr);
            LOG.error(errMsg.toString());
            return null;
        }

        long issueTime = 0;
        SimplePrincipal princ = getSimplePrincipal(username.toLowerCase(), username, issueTime);
        if (princ == null) {
            errMsg.append("AuthorizedAuthHeaderAuthority:authenticate: failed to create principal: user=")
                .append(username);
            LOG.error(errMsg.toString());
            return null;
        }
        princ.setUnsignedCreds(username);
        if (authorizedServiceName != "") {
            princ.setAuthorizedService(authorizedServiceName);
        }
        
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
	            LOG.warn("AuthorizedAuthHeaderAuthority.checkIpAddressMatch: invalid remoteAddr={} message={}", remoteAddr, e.getMessage());
			}
        }
		return false;
    }

    
    static String getCookieValue(HttpServletRequest hreq, String name) {

        jakarta.servlet.http.Cookie[] cookies = hreq.getCookies();
        if (cookies == null) {
            return null;
        }
        for (jakarta.servlet.http.Cookie cookie : cookies) {
            if (name.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }
}
