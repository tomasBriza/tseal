package com.tbr.pki.tseal.policy;

import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.KeyUsage;

import java.time.Duration;
import java.util.function.Consumer;

public final class SigningPolicyBuilder {

    private final PolicyAccumulator accumulator = new PolicyAccumulator();

    SigningPolicyBuilder() {
        accumulator.putSubject(BCStyle.CN, Rules.fromCsr().optional());
        accumulator.putSubject(BCStyle.O, Rules.fromCsr().optional());
        accumulator.keyUsageBits = KeyUsage.keyCertSign | KeyUsage.cRLSign;
        accumulator.ca = true;
        accumulator.pathLen = 0;
        accumulator.setValidity(ValidityRule.fromCsr().optional().orCaller().orDefault(Duration.ofDays(1825)));
    }

    public SigningPolicyBuilder commonName(FieldRule rule) {
        accumulator.putSubject(BCStyle.CN, rule);
        return this;
    }

    public SigningPolicyBuilder organization(FieldRule rule) {
        accumulator.putSubject(BCStyle.O, rule);
        return this;
    }

    public SigningPolicyBuilder country(FieldRule rule) {
        accumulator.putSubject(BCStyle.C, rule);
        return this;
    }

    public SigningPolicyBuilder pathLen(int pathLen) {
        if (pathLen < 0) {
            throw new IllegalArgumentException("pathLen must be >= 0");
        }
        accumulator.ca = true;
        accumulator.endEntity = false;
        accumulator.pathLen = pathLen;
        return this;
    }

    public SigningPolicyBuilder unboundedPathLen() {
        accumulator.ca = true;
        accumulator.endEntity = false;
        accumulator.pathLen = null;
        return this;
    }

    public SigningPolicyBuilder crl(String uri) {
        accumulator.requireUri(uri, "crl");
        accumulator.crlUris.add(uri);
        return this;
    }

    public SigningPolicyBuilder ocsp(String uri) {
        accumulator.requireUri(uri, "ocsp");
        accumulator.ocspUris.add(uri);
        return this;
    }

    public SigningPolicyBuilder caIssuers(String uri) {
        accumulator.requireUri(uri, "caIssuers");
        accumulator.caIssuersUris.add(uri);
        return this;
    }

    public SigningPolicyBuilder validity(ValidityRule rule) {
        accumulator.setValidity(rule);
        return this;
    }

    public SigningPolicyBuilder validity(Duration duration) {
        accumulator.setValidity(duration);
        return this;
    }

    public SigningPolicyBuilder custom(Consumer<RawPolicy> customizer) {
        customizer.accept(new RawPolicyImpl(accumulator));
        return this;
    }

    public IssuancePolicy build() {
        return new IssuancePolicy(accumulator);
    }
}
