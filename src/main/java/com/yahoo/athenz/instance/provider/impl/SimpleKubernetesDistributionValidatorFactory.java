package com.yahoo.athenz.instance.provider.impl;

import com.yahoo.athenz.instance.provider.KubernetesDistributionValidator;
import com.yahoo.athenz.instance.provider.KubernetesDistributionValidatorFactory;

import java.util.HashMap;
import java.util.Map;

public class SimpleKubernetesDistributionValidatorFactory implements KubernetesDistributionValidatorFactory {

    Map<String, KubernetesDistributionValidator> supportedDistributionsMap = new HashMap<>();
    static final String CLOUD_K8S = "k8s";
    
    @Override
    public void initialize() {
        supportedDistributionsMap.put(CLOUD_K8S, DefaultKubernetesValidator.getInstance());
    }

    @Override
    public Map<String, KubernetesDistributionValidator> getSupportedDistributions() {
        return supportedDistributionsMap;
    }
}