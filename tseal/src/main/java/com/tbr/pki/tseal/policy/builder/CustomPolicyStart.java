package com.tbr.pki.tseal.policy.builder;

import com.tbr.pki.tseal.policy.ValidityRule;

import org.bouncycastle.asn1.x509.KeyPurposeId;

import java.time.Duration;
import java.util.function.Consumer;

public interface CustomPolicyStart {
    SubjectRuleBuilder<CustomPolicyStart> subject();
    SanRuleBuilder<CustomPolicyStart> san();
    CustomPolicyStart keyUsage(int bits);
    CustomPolicyStart extendedKeyUsage(KeyPurposeId... purposes);
    CustomPolicyStart endEntity();
    CustomPolicyStart ca(int pathLen);
    CustomPolicyStart caUnbounded();
    CustomPolicyStart crl(String uri);
    CustomPolicyStart ocsp(String uri);
    CustomPolicyStart caIssuers(String uri);
    CustomPolicyStart custom(Consumer<RawPolicy> customizer);
    CustomPolicyBuildable validity(Duration duration);
    CustomPolicyBuildable validity(ValidityRule rule);
}
