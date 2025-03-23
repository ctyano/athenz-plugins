package com.yahoo.athenz.instance.provider.impl;

import com.yahoo.athenz.instance.provider.KubernetesDistributionValidator;
import com.yahoo.athenz.instance.provider.KubernetesDistributionValidatorFactory;

import java.util.HashMap;
import java.util.Map;

public class DefaultKubernetesDistributionValidatorFactory implements KubernetesDistributionValidatorFactory {

    Map<String, KubernetesDistributionValidator> supportedDistributionsMap = new HashMap<>();
    static final String CLOUD_AWS = "aws";
    static final String CLOUD_GCP = "gcp";
    @Override
    public void initialize() {
        supportedDistributionsMap.put(CLOUD_AWS, DefaultAWSElasticKubernetesServiceValidator.getInstance());
        supportedDistributionsMap.put(CLOUD_GCP, DefaultGCPGoogleKubernetesEngineValidator.getInstance());
    }

    @Override
    public Map<String, KubernetesDistributionValidator> getSupportedDistributions() {
        return supportedDistributionsMap;
    }
}