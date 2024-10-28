package com.yahoo.athenz.instance.provider.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.common.server.dns.HostnameResolver;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ProviderResourceException;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.security.PrivateKey;
import java.util.*;

public class InstanceWorkloadIPTokenProvider implements InstanceProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceWorkloadIPTokenProvider.class);
    private static final String URI_HOSTNAME_PREFIX = "athenz://hostname/";

    static final String ZTS_PROP_PROVIDER_DNS_SUFFIX  = "athenz.zts.provider_dns_suffix";
    static final String ZTS_PROP_PRINCIPAL_LIST       = "athenz.zts.provider_service_list";
    static final String ZTS_PROP_EXPIRY_TIME          = "athenz.zts.provider_token_expiry_time";

    static final String ZTS_PROVIDER_SERVICE  = "sys.auth.zts";
    static final String ZTS_INSTANCE_WORKLOAD_IP = "workload_ip";

    public static final String HDR_KEY_ID     = "kid";
    public static final String HDR_TOKEN_TYPE = "typ";
    public static final String HDR_TOKEN_JWT  = "jwt";

    public static final String CLAIM_PROVIDER    = "provider";
    public static final String CLAIM_DOMAIN      = "domain";
    public static final String CLAIM_SERVICE     = "service";
    public static final String CLAIM_CLIENT_ID   = "client_id";
    public static final String CLAIM_INSTANCE_ID = "instance_id";
    public static final String CLAIM_WORKLOAD_IP = "workload_ip";

    KeyStore keyStore = null;
    Set<String> dnsSuffixes = null;
    String provider = null;
    String keyId = null;
    JWSSigner signer = null;
    JWSAlgorithm sigAlg = null;
    PrivateKey key = null;
    Set<String> principals = null;
    HostnameResolver hostnameResolver = null;
    ConfigurableJWTProcessor<SecurityContext> jwtProcessor = null;
    JwtsSigningKeyResolver signingKeyResolver = null;
    int expiryTime;

    @Override
    public Scheme getProviderScheme() {
        return Scheme.CLASS;
    }

    @Override
    public void initialize(String provider, String providerEndpoint, SSLContext sslContext,
            KeyStore keyStore) {

        // save our provider name

        this.provider = provider;

        // obtain list of valid principals for this principal if
        // one is configured

        final String principalList = System.getProperty(ZTS_PROP_PRINCIPAL_LIST);
        if (principalList != null && !principalList.isEmpty()) {
            principals = new HashSet<>(Arrays.asList(principalList.split(",")));
        }

        // determine the dns suffix. if this is not specified we'll just default to zts.athenz.cloud

        dnsSuffixes = new HashSet<>();
        String dnsSuffix = System.getProperty(ZTS_PROP_PROVIDER_DNS_SUFFIX, "zts.athenz.cloud");
        if (StringUtil.isEmpty(dnsSuffix)) {
            dnsSuffix = "zts.athenz.cloud";
        }
        dnsSuffixes.addAll(Arrays.asList(dnsSuffix.split(",")));
    }

    @Override
    public void setPrivateKey(PrivateKey key, String keyId, String sigAlg) {
        this.keyId = keyId;
        this.sigAlg = JWSAlgorithm.parse(sigAlg);
        try {
            this.signer = JwtsHelper.getJWSSigner(key);
        } catch (JOSEException ex) {
            throw new IllegalArgumentException("Unable to create signer: " + ex.getMessage());
        }
    }

    @Override
    public void setHostnameResolver(HostnameResolver hostnameResolver) {
        this.hostnameResolver = hostnameResolver;
    }

    private ProviderResourceException forbiddenError(String message) {
        LOGGER.error(message);
        return new ProviderResourceException(ProviderResourceException.FORBIDDEN, message);
    }

    @Override
    public InstanceConfirmation confirmInstance(InstanceConfirmation confirmation) throws ProviderResourceException {
        return validateInstanceRequest(confirmation, true);
    }

    @Override
    public InstanceConfirmation refreshInstance(InstanceConfirmation confirmation) throws ProviderResourceException {
        return validateInstanceRequest(confirmation, false);
    }

    InstanceConfirmation validateInstanceRequest(InstanceConfirmation confirmation, boolean registerInstance) throws ProviderResourceException {

        // we need to validate the token which is our attestation
        // data for the service requesting a certificate

        final String instanceDomain = confirmation.getDomain();
        final String instanceService = confirmation.getService();

        final Map<String, String> instanceAttributes = confirmation.getAttributes();

        // make sure this service has been configured to be supported
        // by this zts provider

        if (principals != null && !principals.contains(instanceDomain + "." + instanceService)) {
            throw forbiddenError("Service not supported to be launched by ZTS Provider");
        }

        // we're supporting two attestation data models with our provider
        // 1) public / private key pair with service tokens - these
        //    are always starting with v=S1;... string
        // 2) provider registration tokens - using jwts

        final String attestationData = confirmation.getAttestationData();
        if (StringUtil.isEmpty(attestationData)) {
            throw forbiddenError("Service credentials not provided");
        }

        Map<String, String> attributes;

        // for token based request we do support refresh operation

        attributes = Collections.emptyMap();

        final String clientIp = InstanceUtils.getInstanceProperty(instanceAttributes,
                InstanceProvider.ZTS_INSTANCE_CLIENT_IP);
        final String sanIpStr = InstanceUtils.getInstanceProperty(instanceAttributes,
                InstanceProvider.ZTS_INSTANCE_SAN_IP);
        final String hostname = InstanceUtils.getInstanceProperty(instanceAttributes,
                InstanceProvider.ZTS_INSTANCE_HOSTNAME);
        final String sanUri   = InstanceUtils.getInstanceProperty(instanceAttributes,
                InstanceProvider.ZTS_INSTANCE_SAN_URI);

        // validate the IP address if one is provided

        String[] sanIps = null;
        if (sanIpStr != null && !sanIpStr.isEmpty()) {
            sanIps = sanIpStr.split(",");
        }

        if (!validateSanIp(sanIps, clientIp)) {
            throw forbiddenError("Unable to validate request IP address");
        }

        // validate the hostname in payload
        // IP in clientIP can be NATed. For validating hostname, rely on sanIPs, which come
        // from the client, and are already matched with clientIp

        if (!validateHostname(hostname, sanIps)) {
            throw forbiddenError("Unable to validate certificate request hostname");
        }

        // validate san URI
        if (!validateSanUri(sanUri, hostname)) {
            throw forbiddenError("Unable to validate certificate request URI hostname");
        }

        // validate the certificate san DNS names

        StringBuilder instanceId = new StringBuilder(256);
        if (!InstanceUtils.validateCertRequestSanDnsNames(instanceAttributes, instanceDomain,
                instanceService, dnsSuffixes, null, null, false, instanceId, null)) {
            throw forbiddenError("Unable to validate certificate request DNS");
        }

        confirmation.setAttributes(attributes);
        return confirmation;
    }

    /**
     * verifies that at least one of the sanIps matches clientIp
     * @param sanIps an array of SAN IPs
     * @param clientIp the client IP address
     * @return true if sanIps is null or one of the sanIps matches. false otherwise
     */
    boolean validateSanIp(final String[] sanIps, final String clientIp) {

        LOGGER.debug("Validating sanIps: {}, clientIp: {}", sanIps, clientIp);

        // if we have an IP specified in the CSR, one of the sanIp must match our client IP
        if (sanIps == null || sanIps.length == 0) {
            return true;
        }

        if (clientIp == null || clientIp.isEmpty()) {
            return false;
        }

        // It's possible both ipv4, ipv6 addresses are mentioned in sanIP
        for (String sanIp: sanIps) {
            if (sanIp.equals(clientIp)) {
                return true;
            }
        }

        LOGGER.error("Unable to match sanIp: {} with clientIp:{}", sanIps, clientIp);
        return false;
    }

    /**
     * returns true if an empty hostname attribute is passed
     * returns true if a non-empty hostname attribute is passed and all IPs
     * passed in sanIp match the IPs that hostname resolves to.
     * returns false in all other cases
     * @param hostname host name to check against specified IPs
     * @param sanIps list of IPs to check against the specified hostname
     * @return true or false
     */
    boolean validateHostname(final String hostname, final String[] sanIps) {

        LOGGER.debug("Validating hostname: {}, sanIps: {}", hostname, sanIps);

        if (hostname == null || hostname.isEmpty()) {
            LOGGER.info("Request contains no hostname entry for validation");
            // if more than one sanIp is passed, all sanIPs must map to hostname, and hostname is a must
            if (sanIps != null && sanIps.length > 1) {
                LOGGER.error("SanIps:{} > 1, and hostname is empty", sanIps.length);
                return false;
            }
            return true;
        }

        // IP in clientIp can be NATed. Rely on sanIp, which comes from the
        // client, and is already matched with clientIp
        // sanIp should be non-empty

        if (sanIps == null || sanIps.length == 0) {
            LOGGER.error("Request contains no sanIp entry for hostname:{} validation", hostname);
            return false;
        }

        // All entries in sanIP must be one of the IPs that hostname resolves

        Set<String>  hostIps = hostnameResolver.getAllByName(hostname);
        for (String sanIp: sanIps) {
            if (!hostIps.contains(sanIp)) {
                LOGGER.error("One of sanIp: {} is not present in HostIps: {}", hostIps, sanIps);
                return false;
            }
        }

        return true;
    }

    /**
     * verifies if sanUri contains athenz://hostname/, the value matches the hostname
     * @param sanUri the SAN URI that includes athenz hostname
     * @param hostname name of the host to check against
     * @return true if there is no SAN URI or the hostname is included in it, otherwise false
     */
    boolean validateSanUri(final String sanUri, final String hostname) {

        LOGGER.debug("Validating sanUri: {}, hostname: {}", sanUri, hostname);

        if (sanUri == null || sanUri.isEmpty()) {
            LOGGER.info("Request contains no sanURI to verify");
            return true;
        }

        for (String uri: sanUri.split(",")) {
            int idx = uri.indexOf(URI_HOSTNAME_PREFIX);
            if (idx != -1) {
                if (!uri.substring(idx + URI_HOSTNAME_PREFIX.length()).equals(hostname)) {
                    LOGGER.error("SanURI: {} does not contain hostname: {}", sanUri, hostname);
                    return false;
                }
            }
        }

        return true;
    }
}
