package com.tbr.pki.tseal.policy;

import org.bouncycastle.asn1.x509.KeyPurposeId;

import java.time.Duration;
import java.util.function.Consumer;

final class CustomPolicyBuilder implements CustomPolicyStart, CustomPolicyBuildable {

    private final PolicyAccumulator accumulator = new PolicyAccumulator();

    @Override
    public SubjectRuleBuilder<CustomPolicyStart> subject() {
        return new SubjectRuleBuilder<>(accumulator, this);
    }

    @Override
    public SanRuleBuilder<CustomPolicyStart> san() {
        return new SanRuleBuilder<>(accumulator, this);
    }

    @Override
    public CustomPolicyBuilder keyUsage(int bits) {
        accumulator.adaptiveKeyUsage = false;
        accumulator.keyUsageBits = bits;
        return this;
    }

    @Override
    public CustomPolicyBuilder extendedKeyUsage(KeyPurposeId... purposes) {
        accumulator.eku = purposes;
        return this;
    }

    @Override
    public CustomPolicyBuilder endEntity() {
        accumulator.endEntity = true;
        accumulator.ca = false;
        accumulator.pathLen = null;
        return this;
    }

    @Override
    public CustomPolicyBuilder ca(int pathLen) {
        if (pathLen < 0) {
            throw new IllegalArgumentException("pathLen must be >= 0");
        }
        accumulator.endEntity = false;
        accumulator.ca = true;
        accumulator.pathLen = pathLen;
        return this;
    }

    @Override
    public CustomPolicyBuilder caUnbounded() {
        accumulator.endEntity = false;
        accumulator.ca = true;
        accumulator.pathLen = null;
        return this;
    }

    @Override
    public CustomPolicyBuilder crl(String uri) {
        accumulator.requireUri(uri, "crl");
        accumulator.crlUris.add(uri);
        return this;
    }

    @Override
    public CustomPolicyBuilder ocsp(String uri) {
        accumulator.requireUri(uri, "ocsp");
        accumulator.ocspUris.add(uri);
        return this;
    }

    @Override
    public CustomPolicyBuilder caIssuers(String uri) {
        accumulator.requireUri(uri, "caIssuers");
        accumulator.caIssuersUris.add(uri);
        return this;
    }

    @Override
    public CustomPolicyBuilder custom(Consumer<RawPolicy> customizer) {
        customizer.accept(new RawPolicyImpl(accumulator));
        return this;
    }

    @Override
    public CustomPolicyBuilder validity(Duration duration) {
        accumulator.setValidity(duration);
        return this;
    }

    @Override
    public CustomPolicyBuilder validity(ValidityRule rule) {
        accumulator.setValidity(rule);
        return this;
    }

    @Override
    public IssuancePolicy build() {
        return new IssuancePolicy(accumulator);
    }
}
