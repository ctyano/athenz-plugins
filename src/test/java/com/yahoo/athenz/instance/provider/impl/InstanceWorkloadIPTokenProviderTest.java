package com.yahoo.athenz.instance.provider.impl;

import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.token.PrincipalToken;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.server.dns.HostnameResolver;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ProviderResourceException;
import com.yahoo.athenz.zts.InstanceRegisterToken;
import org.mockito.Mockito;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.util.*;

import static org.testng.Assert.*;
import static org.testng.Assert.assertEquals;

public class InstanceWorkloadIPTokenProviderTest {

    private String servicePublicKeyStringK0 = null;
    private String servicePrivateKeyStringK0 = null;

    @BeforeMethod
    public void setup() throws IOException {
        Path path = Paths.get("./src/test/resources/public_k0.key");
        servicePublicKeyStringK0 = new String(Files.readAllBytes(path));

        path = Paths.get("./src/test/resources/unit_test_private_k0.key");
        servicePrivateKeyStringK0 = new String(Files.readAllBytes(path));
    }

    @Test
    public void testInitializeDefaults() {
        InstanceWorkloadIPTokenProvider provider = new InstanceWorkloadIPTokenProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceWorkloadIPTokenProvider", null, null);
        assertTrue(provider.dnsSuffixes.contains("zts.athenz.cloud"));
        assertEquals(InstanceProvider.Scheme.CLASS, provider.getProviderScheme());
        assertNull(provider.keyStore);
        assertNull(provider.principals);
        provider.close();
    }

    @Test
    public void testInitialize() {

        System.setProperty(InstanceWorkloadIPTokenProvider.ZTS_PROP_PROVIDER_DNS_SUFFIX, "zts.cloud");
        System.setProperty(InstanceWorkloadIPTokenProvider.ZTS_PROP_PRINCIPAL_LIST, "athenz.api,sports.backend");

        InstanceWorkloadIPTokenProvider provider = new InstanceWorkloadIPTokenProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceWorkloadIPTokenProvider", null, null);
        assertTrue(provider.dnsSuffixes.contains("zts.cloud"));
        assertNull(provider.keyStore);
        assertEquals(provider.principals.size(), 2);
        assertTrue(provider.principals.contains("athenz.api"));
        assertTrue(provider.principals.contains("sports.backend"));
        provider.close();

        System.setProperty(InstanceWorkloadIPTokenProvider.ZTS_PROP_PROVIDER_DNS_SUFFIX, "");
        System.setProperty(InstanceWorkloadIPTokenProvider.ZTS_PROP_PRINCIPAL_LIST, "");

        provider = new InstanceWorkloadIPTokenProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceWorkloadIPTokenProvider", null, null);
        assertTrue(provider.dnsSuffixes.contains("zts.athenz.cloud"));
        assertNull(provider.keyStore);
        assertNull(provider.principals);
        provider.close();
        System.clearProperty(InstanceWorkloadIPTokenProvider.ZTS_PROP_PROVIDER_DNS_SUFFIX);
    }

    @Test
    public void testRefreshInstance() throws ProviderResourceException {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        System.setProperty(InstanceWorkloadIPTokenProvider.ZTS_PROP_PRINCIPAL_LIST, "sports.api");

        InstanceWorkloadIPTokenProvider provider = new InstanceWorkloadIPTokenProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceWorkloadIPTokenProvider", null, keystore);

        PrincipalToken tokenToSign = new PrincipalToken.Builder("S1", "sports", "api")
                .keyId("v0").salt("salt").issueTime(System.currentTimeMillis() / 1000)
                .expirationWindow(3600).build();
        tokenToSign.sign(servicePrivateKeyStringK0);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData(tokenToSign.getSignedToken());
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.zts");

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.zts.athenz.cloud,inst1.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CSR_PUBLIC_KEY, servicePublicKeyStringK0);
        confirmation.setAttributes(attributes);

        assertNotNull(provider.refreshInstance(confirmation));
        provider.close();
        System.clearProperty(InstanceWorkloadIPTokenProvider.ZTS_PROP_PRINCIPAL_LIST);
    }

    @Test
    public void testValidateSanIp() {

        InstanceWorkloadIPTokenProvider provider = new InstanceWorkloadIPTokenProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceWorkloadIPTokenProvider", null, null);
        assertTrue(provider.validateSanIp(new String[]{"10.1.1.1"}, "10.1.1.1"));
        assertTrue(provider.validateSanIp(null, "10.1.1.1"));
        assertTrue(provider.validateSanIp(new String[]{}, "10.1.1.1"));
        assertFalse(provider.validateSanIp(new String[]{""}, "10.1.1.1"));
        assertFalse(provider.validateSanIp(new String[]{"10.1.1.2"}, "10.1.1.1"));
        assertFalse(provider.validateSanIp(new String[]{"10.1.1.2"}, null));
        assertFalse(provider.validateSanIp(new String[]{"10.1.1.2"}, ""));

        // ipv6
        assertTrue(provider.validateSanIp(new String[]{"2001:db8:a0b:12f0:0:0:0:1"}, "2001:db8:a0b:12f0:0:0:0:1"));
        assertTrue(provider.validateSanIp(null, "2001:db8:a0b:12f0:0:0:0:1"));
        assertTrue(provider.validateSanIp(new String[]{}, "2001:db8:a0b:12f0:0:0:0:1"));
        assertFalse(provider.validateSanIp(new String[]{"2002:db9:a0b:12f0:0:0:0:1"}, "2001:db8:a0b:12f0:0:0:0:1"));
        assertFalse(provider.validateSanIp(new String[]{"2002:db9:a0b:12f0:0:0:0:1"}, "10.1.1.1"));
        assertFalse(provider.validateSanIp(new String[]{"2002:db9:a0b:12f0:0:0:0:1"}, null));
        assertFalse(provider.validateSanIp(new String[]{"2002:db9:a0b:12f0:0:0:0:1"}, ""));

        // ipv4 and ipv6 mixed
        assertTrue(provider.validateSanIp(new String[]{"10.1.1.1", "2001:db8:a0b:12f0:0:0:0:1"}, "10.1.1.1"));
        assertTrue(provider.validateSanIp(new String[]{"10.1.1.1", "2001:db8:a0b:12f0:0:0:0:1"}, "2001:db8:a0b:12f0:0:0:0:1"));
        assertFalse(provider.validateSanIp(new String[]{"10.1.1.1", "2001:db8:a0b:12f0:0:0:0:1"}, "10.1.1.2"));
        assertFalse(provider.validateSanIp(new String[]{"10.1.1.1", "2001:db8:a0b:12f0:0:0:0:1"}, null));
        assertFalse(provider.validateSanIp(new String[]{"10.1.1.1", "2001:db8:a0b:12f0:0:0:0:1"}, ""));

        provider.close();
    }

    @Test
    public void testValidateHostname() {
        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        Mockito.when(hostnameResolver.getAllByName("abc.athenz.com"))
               .thenReturn(new HashSet<>(Arrays.asList("10.1.1.1", "2001:db8:a0b:12f0:0:0:0:1")));

        InstanceWorkloadIPTokenProvider provider = new InstanceWorkloadIPTokenProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceWorkloadIPTokenProvider", null, null);
        provider.setHostnameResolver(hostnameResolver);

        assertTrue(provider.validateHostname("abc.athenz.com", new String[]{"10.1.1.1"}));
        assertTrue(provider.validateHostname("abc.athenz.com", new String[]{"10.1.1.1", "2001:db8:a0b:12f0:0:0:0:1"}));
        assertFalse(provider.validateHostname("abc.athenz.com", new String[]{"10.1.1.2"}));
        assertFalse(provider.validateHostname("abc.athenz.com", new String[]{"10.1.1.1", "1:2:3:4:5:6:7:8"}));
        assertFalse(provider.validateHostname("abc.athenz.com", new String[]{"10.1.1.2", "1:2:3:4:5:6:7:8"}));

        // If hostname is passed, sanIp must be non empty
        assertFalse(provider.validateHostname("abc.athenz.com", null));
        assertFalse(provider.validateHostname("abc.athenz.com", new String[]{}));
        assertFalse(provider.validateHostname("abc.athenz.com", new String[]{""}));

        // It's possible client didn't set Hostname payload. One sanIp be optionally set, and would have been matched with clientIp upstream
        assertTrue(provider.validateHostname("", new String[]{"10.1.1.1"}));
        assertTrue(provider.validateHostname(null, new String[]{"10.1.1.1"}));

        // If more than one sanIp is passed, hostname must be non empty
        assertFalse(provider.validateHostname(null, new String[]{"10.1.1.1", "2001:db8:a0b:12f0:0:0:0:1"}));
        assertFalse(provider.validateHostname("", new String[]{"10.1.1.1", "2001:db8:a0b:12f0:0:0:0:1"}));

        provider.close();
    }

    @Test
    public void testValidateSanUri() {
        InstanceWorkloadIPTokenProvider provider = new InstanceWorkloadIPTokenProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceWorkloadIPTokenProvider", null, null);
        assertTrue(provider.validateSanUri("athenz://hostname/abc.athenz.com", "abc.athenz.com"));
        assertTrue(provider.validateSanUri("spiffe://movies/sa/writer,athenz://hostname/abc.athenz.com", "abc.athenz.com"));
        assertTrue(provider.validateSanUri("spiffe://movies/sa/writer,athenz://hostname/abc.athenz.com,athenz://instanceid/zts/abc.athenz.com", "abc.athenz.com"));
        assertTrue(provider.validateSanUri("spiffe://movies/sa/writer,athenz://hostname/abc.athenz.com,athenz://hostname/abc.athenz.com", "abc.athenz.com"));

        assertTrue(provider.validateSanUri("", "abc.athenz.com"));
        assertTrue(provider.validateSanUri(null, "abc.athenz.com"));

        assertFalse(provider.validateSanUri("athenz://hostname/abc.athenz.cm", "def.athenz.com"));
        assertFalse(provider.validateSanUri("spiffe://movies/sa/writer,    athenz://hostname/abc.athenz.cm", "def.athenz.com"));
        assertFalse(provider.validateSanUri("spiffe://movies/sa/writer,athenz://hostname/abc.athenz.com,athenz://hostname/def.athenz.com", "abc.athenz.com"));
        provider.close();
    }

    @Test
    public void testAuthenticate() {

        InstanceWorkloadIPTokenProvider provider = new InstanceWorkloadIPTokenProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceWorkloadIPTokenProvider", null, null);

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        provider.close();
    }

    @Test
    public void testValidateToken() {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        InstanceWorkloadIPTokenProvider provider = new InstanceWorkloadIPTokenProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceWorkloadIPTokenProvider", null, keystore);
        StringBuilder errMsg = new StringBuilder(256);

        errMsg.setLength(0);

        provider.close();
    }

    @Test
    public void testConfirmInstance() throws ProviderResourceException {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        System.setProperty(InstanceWorkloadIPTokenProvider.ZTS_PROP_PRINCIPAL_LIST, "sports.api");

        InstanceWorkloadIPTokenProvider provider = new InstanceWorkloadIPTokenProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceWorkloadIPTokenProvider", null, keystore);

        PrincipalToken tokenToSign = new PrincipalToken.Builder("S1", "sports", "api")
                .keyId("v0").salt("salt").issueTime(System.currentTimeMillis() / 1000)
                .expirationWindow(3600).build();
        tokenToSign.sign(servicePrivateKeyStringK0);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData(tokenToSign.getSignedToken());
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.zts");

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.zts.athenz.cloud,inst1.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CSR_PUBLIC_KEY, servicePublicKeyStringK0);
        confirmation.setAttributes(attributes);

        assertNotNull(provider.confirmInstance(confirmation));
        provider.close();
        System.clearProperty(InstanceWorkloadIPTokenProvider.ZTS_PROP_PRINCIPAL_LIST);
    }

    @Test
    public void testConfirmInstanceUnsupportedService() {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        System.setProperty(InstanceWorkloadIPTokenProvider.ZTS_PROP_PRINCIPAL_LIST, "sports.api");

        InstanceWorkloadIPTokenProvider provider = new InstanceWorkloadIPTokenProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceWorkloadIPTokenProvider", null, keystore);

        PrincipalToken tokenToSign = new PrincipalToken.Builder("S1", "sports", "backend")
                .keyId("v0").salt("salt").issueTime(System.currentTimeMillis() / 1000)
                .expirationWindow(3600).build();
        tokenToSign.sign(servicePrivateKeyStringK0);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData(tokenToSign.getSignedToken());
        confirmation.setDomain("sports");
        confirmation.setService("backend");
        confirmation.setProvider("sys.auth.zts");

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "backend.sports.zts.athenz.cloud,inst1.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CSR_PUBLIC_KEY, servicePublicKeyStringK0);
        confirmation.setAttributes(attributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertTrue(ex.getMessage().contains("Service not supported to be launched by ZTS Provider"));
        }
        provider.close();
        System.clearProperty(InstanceWorkloadIPTokenProvider.ZTS_PROP_PRINCIPAL_LIST);
    }

    @Test
    public void testConfirmInstanceValidHostname() throws ProviderResourceException {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        Mockito.when(hostnameResolver.isValidHostname("hostabc.athenz.com")).thenReturn(true);
        Mockito.when(hostnameResolver.getAllByName("hostabc.athenz.com")).thenReturn(
                new HashSet<>(Arrays.asList("10.1.1.1", "2001:db8:a0b:12f0:0:0:0:1"))
        );

        InstanceWorkloadIPTokenProvider provider = new InstanceWorkloadIPTokenProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceWorkloadIPTokenProvider", null, keystore);
        provider.setHostnameResolver(hostnameResolver);

        PrincipalToken tokenToSign = new PrincipalToken.Builder("S1", "sports", "api")
                .keyId("v0").salt("salt").issueTime(System.currentTimeMillis() / 1000)
                .expirationWindow(3600).build();
        tokenToSign.sign(servicePrivateKeyStringK0);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData(tokenToSign.getSignedToken());
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.zts");

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.zts.athenz.cloud,inst1.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_HOSTNAME, "hostabc.athenz.com");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CLIENT_IP, "10.1.1.1");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_IP, "10.1.1.1,2001:db8:a0b:12f0:0:0:0:1");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "athenz://instanceid/zts/hostabc.athenz.com,athenz://hostname/hostabc.athenz.com");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CSR_PUBLIC_KEY, servicePublicKeyStringK0);
        confirmation.setAttributes(attributes);

        assertNotNull(provider.confirmInstance(confirmation));
        provider.close();
    }

    @Test
    public void testConfirmInstanceValidHostnameIpv6() throws ProviderResourceException {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        Mockito.when(hostnameResolver.isValidHostname("hostabc.athenz.com")).thenReturn(true);
        Mockito.when(hostnameResolver.getAllByName("hostabc.athenz.com")).thenReturn(
                new HashSet<>(Arrays.asList("10.1.1.1", "2001:db8:a0b:12f0:0:0:0:1"))
        );

        InstanceWorkloadIPTokenProvider provider = new InstanceWorkloadIPTokenProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceWorkloadIPTokenProvider", null, keystore);
        provider.setHostnameResolver(hostnameResolver);

        PrincipalToken tokenToSign = new PrincipalToken.Builder("S1", "sports", "api")
                .keyId("v0").salt("salt").issueTime(System.currentTimeMillis() / 1000)
                .expirationWindow(3600).build();
        tokenToSign.sign(servicePrivateKeyStringK0);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData(tokenToSign.getSignedToken());
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.zts");

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.zts.athenz.cloud,inst1.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_HOSTNAME, "hostabc.athenz.com");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CLIENT_IP, "2001:db8:a0b:12f0:0:0:0:1");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_IP, "10.1.1.1,2001:db8:a0b:12f0:0:0:0:1");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "athenz://instanceid/zts/hostabc.athenz.com,athenz://hostname/hostabc.athenz.com");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CSR_PUBLIC_KEY, servicePublicKeyStringK0);
        confirmation.setAttributes(attributes);

        assertNotNull(provider.confirmInstance(confirmation));
        provider.close();
    }

    @Test
    public void testConfirmInstanceUnknownHostname() {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        Mockito.when(hostnameResolver.isValidHostname("hostabc.athenz.com")).thenReturn(true);
        Mockito.when(hostnameResolver.getAllByName("hostabc.athenz.com")).thenReturn(new HashSet<>(Collections.singletonList("10.1.1.2")));

        InstanceWorkloadIPTokenProvider provider = new InstanceWorkloadIPTokenProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceWorkloadIPTokenProvider", null, keystore);
        provider.setHostnameResolver(hostnameResolver);

        PrincipalToken tokenToSign = new PrincipalToken.Builder("S1", "sports", "api")
                .keyId("v0").salt("salt").issueTime(System.currentTimeMillis() / 1000)
                .expirationWindow(3600).build();
        tokenToSign.sign(servicePrivateKeyStringK0);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData(tokenToSign.getSignedToken());
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.zts");

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.zts.athenz.cloud,inst1.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_HOSTNAME, "hostabc.athenz.com");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CLIENT_IP, "10.1.1.1");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_IP, "10.1.1.1");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CSR_PUBLIC_KEY, servicePublicKeyStringK0);
        confirmation.setAttributes(attributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("validate certificate request hostname"));
        }
        provider.close();
    }

    @Test
    public void testConfirmInstanceInvalidHostnameUri() {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        Mockito.when(hostnameResolver.isValidHostname("hostabc.athenz.com")).thenReturn(true);
        Mockito.when(hostnameResolver.getAllByName("hostabc.athenz.com")).thenReturn(new HashSet<>(Collections.singletonList("10.1.1.1")));

        InstanceWorkloadIPTokenProvider provider = new InstanceWorkloadIPTokenProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceWorkloadIPTokenProvider", null, keystore);
        provider.setHostnameResolver(hostnameResolver);

        PrincipalToken tokenToSign = new PrincipalToken.Builder("S1", "sports", "api")
                .keyId("v0").salt("salt").issueTime(System.currentTimeMillis() / 1000)
                .expirationWindow(3600).build();
        tokenToSign.sign(servicePrivateKeyStringK0);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData(tokenToSign.getSignedToken());
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.zts");

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.zts.athenz.cloud,inst1.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_HOSTNAME, "hostabc.athenz.com");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CLIENT_IP, "10.1.1.1");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_IP, "10.1.1.1");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "athenz://instanceid/zts/def.athenz.com,athenz://hostname/def.athenz.com");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CSR_PUBLIC_KEY, servicePublicKeyStringK0);
        confirmation.setAttributes(attributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("validate certificate request URI hostname"));
        }
        provider.close();
    }

    @Test
    public void testConfirmInstanceInvalidIP() {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        InstanceWorkloadIPTokenProvider provider = new InstanceWorkloadIPTokenProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceWorkloadIPTokenProvider", null, keystore);

        PrincipalToken tokenToSign = new PrincipalToken.Builder("S1", "sports", "api")
                .keyId("v0").salt("salt").issueTime(System.currentTimeMillis() / 1000)
                .expirationWindow(3600).build();
        tokenToSign.sign(servicePrivateKeyStringK0);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData(tokenToSign.getSignedToken());
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.zts");

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.zts.athenz.cloud,inst1.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CLIENT_IP, "10.1.1.1");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_IP, "10.1.1.2");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CSR_PUBLIC_KEY, servicePublicKeyStringK0);
        confirmation.setAttributes(attributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("validate request IP address"));
        }
        provider.close();
    }

    @Test
    public void testConfirmInstanceInvalidDNSName() {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        InstanceWorkloadIPTokenProvider provider = new InstanceWorkloadIPTokenProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceWorkloadIPTokenProvider", null, keystore);

        PrincipalToken tokenToSign = new PrincipalToken.Builder("S1", "sports", "api")
                .keyId("v0").salt("salt").issueTime(System.currentTimeMillis() / 1000)
                .expirationWindow(3600).build();
        tokenToSign.sign(servicePrivateKeyStringK0);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData(tokenToSign.getSignedToken());
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.zts");

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.weather.zts.athenz.cloud,inst1.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CLIENT_IP, "10.1.1.1");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_IP, "10.1.1.1");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CSR_PUBLIC_KEY, servicePublicKeyStringK0);
        confirmation.setAttributes(attributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("validate certificate request DNS"));
        }
        provider.close();
    }

    @Test
    public void testConfirmInstanceEmptyCredentials() {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        System.setProperty(InstanceWorkloadIPTokenProvider.ZTS_PROP_PRINCIPAL_LIST, "sports.api");

        // get our ec public key

        InstanceWorkloadIPTokenProvider provider = new InstanceWorkloadIPTokenProvider();
        provider.initialize("sys.auth.zts", "com.yahoo.athenz.instance.provider.impl.InstanceWorkloadIPTokenProvider", null, keystore);

        InstanceConfirmation tokenConfirmation = new InstanceConfirmation();
        tokenConfirmation.setDomain("sports");
        tokenConfirmation.setService("api");
        tokenConfirmation.setProvider("sys.auth.zts");
        Map<String, String> attrs = new HashMap<>();
        attrs.put(InstanceProvider.ZTS_INSTANCE_ID, "id001");
        tokenConfirmation.setAttributes(attrs);

        // generate instance confirmation

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.zts");

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.zts.athenz.cloud,id001.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CSR_PUBLIC_KEY, servicePublicKeyStringK0);
        attributes.put(InstanceProvider.ZTS_INSTANCE_ID, "id001");
        confirmation.setAttributes(attributes);

        // provider mismatch

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Service credentials not provided"));
        }

        provider.close();
        System.clearProperty(InstanceWorkloadIPTokenProvider.ZTS_PROP_PRINCIPAL_LIST);
    }
}