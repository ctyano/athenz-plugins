package com.yahoo.athenz.auth.impl;

import com.yahoo.athenz.auth.Principal;

import jakarta.servlet.http.HttpServletRequest;

import org.mockito.Mockito;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class AuthorizedAuthHeaderAuthorityTest {

    @Test
    public void testGetID() {
    	AuthorizedAuthHeaderAuthority aaha = new AuthorizedAuthHeaderAuthority();
        assertEquals(aaha.getID(), "Authorized-Auth-Header");
    }

    @Test
    public void testGetDomain() {
        AuthorizedAuthHeaderAuthority aaha = new AuthorizedAuthHeaderAuthority();
        assertEquals(aaha.getDomain(), "user");
    }

    @Test
    public void testGetHeader() {
        AuthorizedAuthHeaderAuthority aaha = new AuthorizedAuthHeaderAuthority();
        assertEquals(aaha.getHeader(), "X-Auth-User");
    }

    @Test
    public void testGetAuthenticateChallenge() {
        AuthorizedAuthHeaderAuthority aaha = new AuthorizedAuthHeaderAuthority();
        assertEquals(aaha.getAuthenticateChallenge(), null);
    }

    @Test
    public void testAllowAuthorization() {
        AuthorizedAuthHeaderAuthority aaha = new AuthorizedAuthHeaderAuthority();
        assertTrue(aaha.allowAuthorization());
    }

    @Test
    public void testAuthenticate() {
        AuthorizedAuthHeaderAuthority aaha = new AuthorizedAuthHeaderAuthority();
        StringBuilder errMsg = new StringBuilder();

        try {
        	System.setProperty(AuthorizedAuthHeaderAuthority.ATHENZ_PROP_AUTH_HEADER_TRUSTED_CIDR, "127.0.0.1,192.168.0.1");
        	aaha.initialize();
        }catch (Exception ex) {
            fail();
        }
        
        String testUser = "athenz-admin";
        String testAuthorizedService = "authorized-service";
        String remoteAddr = "127.0.0.1";

        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(httpServletRequest.getHeader(AuthorizedAuthHeaderAuthority.AUTH_HEADER_USER_DEFAULT)).thenReturn(testUser);
        Mockito.when(httpServletRequest.getHeader(AuthorizedAuthHeaderAuthority.AUTH_HEADER_AUTHORIZED_SERVICE_DEFAULT)).thenReturn(testAuthorizedService);
        Mockito.when(httpServletRequest.getRemoteAddr()).thenReturn(remoteAddr);
        
        // happy path
        Principal principal = aaha.authenticate(httpServletRequest, errMsg);
        assertNotNull(principal);
        assertEquals(errMsg.toString(), "");

        // untrusted remote ip
        errMsg = new StringBuilder();
        Mockito.when(httpServletRequest.getRemoteAddr()).thenReturn("192.168.0.2");
        principal = aaha.authenticate(httpServletRequest, errMsg);
        assertNull(principal);
        assertEquals(errMsg.toString(), "AuthorizedAuthHeaderAuthority:authenticate: remote ip address is not trusted: ip=192.168.0.2");

        // Failed to create principal
        errMsg = new StringBuilder();
        Mockito.when(httpServletRequest.getRemoteAddr()).thenReturn(remoteAddr);
        Mockito.when(httpServletRequest.getHeader(AuthorizedAuthHeaderAuthority.AUTH_HEADER_USER_DEFAULT)).thenReturn("");
        principal = aaha.authenticate(httpServletRequest, errMsg);
        assertNull(principal);
        assertEquals(errMsg.toString(), "AuthorizedAuthHeaderAuthority.authenticate: invalid user= authorized service=authorized-service");
    }

    @Test
    public void testGetSimplePrincipal() {
        AuthorizedAuthHeaderAuthority aaha = new AuthorizedAuthHeaderAuthority();
        long issueTime = System.currentTimeMillis();
        SimplePrincipal sp = aaha.getSimplePrincipal("abc", "xyz", issueTime);
        assertNotNull(sp);
        assertEquals(sp.getAuthority().getClass(), AuthorizedAuthHeaderAuthority.class);
    }
}
