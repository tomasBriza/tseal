package com.tbr.pki.tseal.policy;

import org.bouncycastle.asn1.x509.KeyPurposeId;

import java.time.Duration;
import java.util.function.Consumer;

public interface CustomPolicyBuildable extends CustomPolicyStart {
    @Override CustomPolicyBuildable keyUsage(int bits);
    @Override CustomPolicyBuildable extendedKeyUsage(KeyPurposeId... purposes);
    @Override CustomPolicyBuildable endEntity();
    @Override CustomPolicyBuildable ca(int pathLen);
    @Override CustomPolicyBuildable caUnbounded();
    @Override CustomPolicyBuildable crl(String uri);
    @Override CustomPolicyBuildable ocsp(String uri);
    @Override CustomPolicyBuildable caIssuers(String uri);
    @Override CustomPolicyBuildable custom(Consumer<RawPolicy> customizer);
    @Override CustomPolicyBuildable validity(Duration duration);
    @Override CustomPolicyBuildable validity(ValidityRule rule);
    IssuancePolicy build();
}
