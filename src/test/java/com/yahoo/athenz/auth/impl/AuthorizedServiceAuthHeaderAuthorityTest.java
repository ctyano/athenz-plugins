package com.yahoo.athenz.auth.impl;

import com.yahoo.athenz.auth.Principal;

import jakarta.servlet.http.HttpServletRequest;

import org.mockito.Mockito;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class AuthorizedServiceAuthHeaderAuthorityTest {

    @Test
    public void testGetID() {
    	AuthorizedServiceAuthHeaderAuthority aaha = new AuthorizedServiceAuthHeaderAuthority();
        assertEquals(aaha.getID(), "X-Auth-Authorized-Service");
    }

    @Test
    public void testGetDomain() {
        AuthorizedServiceAuthHeaderAuthority aaha = new AuthorizedServiceAuthHeaderAuthority();
        assertEquals(aaha.getDomain(), "user");
    }

    @Test
    public void testGetAuthorizedServiceAuthHeader() {
        AuthorizedServiceAuthHeaderAuthority aaha = new AuthorizedServiceAuthHeaderAuthority();
        assertEquals(aaha.getHeader(), "X-Auth-User");
    }

    @Test
    public void testGetAuthenticateChallenge() {
        AuthorizedServiceAuthHeaderAuthority aaha = new AuthorizedServiceAuthHeaderAuthority();
        assertEquals(aaha.getAuthenticateChallenge(), null);
    }

    @Test
    public void testAllowAuthorization() {
        AuthorizedServiceAuthHeaderAuthority aaha = new AuthorizedServiceAuthHeaderAuthority();
        assertTrue(aaha.allowAuthorization());
    }

    @Test
    public void testAuthenticate() {
        AuthorizedServiceAuthHeaderAuthority aaha = new AuthorizedServiceAuthHeaderAuthority();
        StringBuilder errMsg = new StringBuilder();

        try {
        	System.setProperty(AuthorizedServiceAuthHeaderAuthority.ATHENZ_PROP_AUTH_HEADER_TRUSTED_CIDR, "127.0.0.1,192.168.0.1");
        	aaha.initialize();
        }catch (Exception ex) {
            fail();
        }
        
        String testUser = "athenz-admin";
        String testAuthorizedService = "authorized-service";
        String remoteAddr = "127.0.0.1";

        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(httpServletRequest.getHeader(AuthorizedServiceAuthHeaderAuthority.AUTH_HEADER_USER_DEFAULT)).thenReturn(testUser);
        Mockito.when(httpServletRequest.getHeader(AuthorizedServiceAuthHeaderAuthority.AUTH_HEADER_AUTHORIZED_SERVICE_DEFAULT)).thenReturn(testAuthorizedService);
        Mockito.when(httpServletRequest.getRemoteAddr()).thenReturn(remoteAddr);
        
        // happy path
        Principal principal = aaha.authenticate(httpServletRequest, errMsg);
        assertNotNull(principal);
        assertEquals(errMsg.toString(), "");

        // untrusted remote ip
        errMsg = new StringBuilder();
        Mockito.when(httpServletRequest.getHeader(AuthorizedServiceAuthHeaderAuthority.AUTH_HEADER_USER_DEFAULT)).thenReturn(testUser);
        Mockito.when(httpServletRequest.getHeader(AuthorizedServiceAuthHeaderAuthority.AUTH_HEADER_AUTHORIZED_SERVICE_DEFAULT)).thenReturn(testAuthorizedService);
        Mockito.when(httpServletRequest.getRemoteAddr()).thenReturn("192.168.0.2");
        principal = aaha.authenticate(httpServletRequest, errMsg);
        assertNull(principal);
        assertEquals(errMsg.toString(), "AuthorizedServiceAuthHeaderAuthority:authenticate: remote ip address is not trusted: ip=192.168.0.2");

        // Failed to create principal
        errMsg = new StringBuilder();
        Mockito.when(httpServletRequest.getHeader(AuthorizedServiceAuthHeaderAuthority.AUTH_HEADER_USER_DEFAULT)).thenReturn(null);
        Mockito.when(httpServletRequest.getHeader(AuthorizedServiceAuthHeaderAuthority.AUTH_HEADER_AUTHORIZED_SERVICE_DEFAULT)).thenReturn(testAuthorizedService);
        Mockito.when(httpServletRequest.getRemoteAddr()).thenReturn(remoteAddr);
        principal = aaha.authenticate(httpServletRequest, errMsg);
        assertNull(principal);
        assertEquals(errMsg.toString(), "");
    }

    @Test
    public void testGetSimplePrincipal() {
        AuthorizedServiceAuthHeaderAuthority aaha = new AuthorizedServiceAuthHeaderAuthority();
        long issueTime = System.currentTimeMillis();
        SimplePrincipal sp = aaha.getSimplePrincipal("abc", "xyz", issueTime);
        assertNotNull(sp);
        assertEquals(sp.getAuthority().getClass(), AuthorizedServiceAuthHeaderAuthority.class);
    }
}
