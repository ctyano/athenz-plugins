package com.yahoo.athenz.instance.provider.impl;

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import javax.net.ssl.SSLContext;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;
import java.util.*;

import static com.yahoo.athenz.instance.provider.impl.InstanceGCPProvider.*;

public class DefaultKubernetesValidator extends CommonKubernetesDistributionValidator {

    private static final Logger LOGGER = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    Set<String> k8sDNSSuffixes;

    private static final DefaultKubernetesValidator INSTANCE = new DefaultKubernetesValidator();
    static final String K8S_OIDC_ISSUER                   = "https://kubernetes.default.svc.cluster.local";
    static final String K8S_PROP_BOOT_TIME_OFFSET         = "athenz.zts.k8s_boot_time_offset";
    static final String K8S_PROP_DNS_SUFFIX               = "athenz.zts.k8s_dns_suffix";

    public static DefaultKubernetesValidator getInstance() {
        return INSTANCE;
    }
    private DefaultKubernetesValidator() {
    }

    @Override
    public void initialize(final SSLContext sslContext, Authorizer authorizer) {
        super.initialize(sslContext, authorizer);
        final String dnsSuffix = System.getProperty(K8S_PROP_DNS_SUFFIX);
        if (!StringUtil.isEmpty(dnsSuffix)) {
            k8sDNSSuffixes.addAll(Arrays.asList(dnsSuffix.split(",")));
        }
    }

    @Override
    public String validateIssuer(InstanceConfirmation confirmation, IdTokenAttestationData attestationData, StringBuilder errMsg) {
        String issuer = getIssuerFromToken(attestationData, errMsg);
        if (StringUtil.isEmpty(issuer)) {
            errMsg.append("Issuer is empty");
            return null;
        }
        if (!issuer.equals(K8S_OIDC_ISSUER)) {
            errMsg.append("Issuer is not ").append(K8S_OIDC_ISSUER);
            return null;
        }
        final Map<String, String> instanceAttributes = confirmation.getAttributes();
        final String cloudName = InstanceUtils.getInstanceProperty(instanceAttributes, ZTS_INSTANCE_CLOUD);
        final String providerName = confirmation.getProvider();
        final String k8sNamespaceName = attestationData.getIdentityToken();
        final String k8sServiceAccountName = attestationData.getIdentityToken();

        final String domainName = confirmation.getDomain();
        final String serviceName = confirmation.getService();
        // attribute set after verification above or attribute validation
        final String resource = String.format("cloud:%s:provider:%s:system:serviceaccount:%s:%s", cloudName, providerName, k8sNamespaceName, k8sServiceAccountName);

        Principal principal = SimplePrincipal.create(domainName, serviceName, (String) null);
        boolean accessCheck = authorizer.access(ACTION_LAUNCH, resource, principal, null);
        if (!accessCheck) {
            errMsg.append("k8s launch authorization check failed for action: ").append(ACTION_LAUNCH)
                    .append(" resource: ").append(resource);
            return null;
        }
        return issuer;
    }

    @Override
    public boolean validateSanDNSEntries(InstanceConfirmation confirmation, StringBuilder errMsg) {
        StringBuilder instanceId = new StringBuilder(256);
        final Map<String, String> instanceAttributes = confirmation.getAttributes();
        final String cloudName = InstanceUtils.getInstanceProperty(instanceAttributes, ZTS_INSTANCE_CLOUD);
        if (StringUtil.isEmpty(cloudName) || cloudName.equals("")) {
            errMsg.append("Unable to find cloud name");
            return false;
        }
        if (!InstanceUtils.validateCertRequestSanDnsNames(instanceAttributes, confirmation.getDomain(),
                confirmation.getService(), k8sDNSSuffixes, null, null, false, instanceId, null)) {
            errMsg.append("Unable to validate certificate request hostnames for SAN DNS names");
            return false;
        }
        return true;
    }
}
