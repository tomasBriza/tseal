package com.tbr.pki.tseal.policy;

import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;

import java.time.Duration;
import java.util.function.Consumer;

public final class HttpsPolicyBuilder {

    private final PolicyAccumulator accumulator = new PolicyAccumulator();

    HttpsPolicyBuilder() {
        accumulator.putSubject(BCStyle.CN, Rules.fromCsr().optional());
        accumulator.putSanType(GeneralName.dNSName, Rules.fromCsr().optional());
        accumulator.putSanType(GeneralName.iPAddress, Rules.fromCsr().optional());
        accumulator.atLeastOneSan = true;
        accumulator.adaptiveKeyUsage = true;
        accumulator.eku = new KeyPurposeId[] { KeyPurposeId.id_kp_serverAuth };
        accumulator.endEntity = true;
        accumulator.setValidity(ValidityRule.fromCsr().optional().orCaller().orDefault(Duration.ofDays(90)));
    }

    public HttpsPolicyBuilder commonName(FieldRule rule) {
        accumulator.putSubject(BCStyle.CN, rule);
        return this;
    }

    public HttpsPolicyBuilder organization(FieldRule rule) {
        accumulator.putSubject(BCStyle.O, rule);
        return this;
    }

    public HttpsPolicyBuilder country(FieldRule rule) {
        accumulator.putSubject(BCStyle.C, rule);
        return this;
    }

    public HttpsPolicyBuilder dns(FieldRule rule) {
        accumulator.putSanType(GeneralName.dNSName, rule);
        return this;
    }

    public HttpsPolicyBuilder ip(FieldRule rule) {
        accumulator.putSanType(GeneralName.iPAddress, rule);
        return this;
    }

    public HttpsPolicyBuilder crl(String uri) {
        accumulator.requireUri(uri, "crl");
        accumulator.crlUris.add(uri);
        return this;
    }

    public HttpsPolicyBuilder ocsp(String uri) {
        accumulator.requireUri(uri, "ocsp");
        accumulator.ocspUris.add(uri);
        return this;
    }

    public HttpsPolicyBuilder caIssuers(String uri) {
        accumulator.requireUri(uri, "caIssuers");
        accumulator.caIssuersUris.add(uri);
        return this;
    }

    public HttpsPolicyBuilder validity(ValidityRule rule) {
        accumulator.setValidity(rule);
        return this;
    }

    public HttpsPolicyBuilder validity(Duration duration) {
        accumulator.setValidity(duration);
        return this;
    }

    public HttpsPolicyBuilder custom(Consumer<RawPolicy> customizer) {
        customizer.accept(new RawPolicyImpl(accumulator));
        return this;
    }

    public IssuancePolicy build() {
        return new IssuancePolicy(accumulator);
    }
}
