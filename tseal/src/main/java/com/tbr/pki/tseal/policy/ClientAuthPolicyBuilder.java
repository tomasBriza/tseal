package com.tbr.pki.tseal.policy;

import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;

import java.time.Duration;
import java.util.function.Consumer;

public final class ClientAuthPolicyBuilder {

    private final PolicyAccumulator accumulator = new PolicyAccumulator();

    ClientAuthPolicyBuilder() {
        accumulator.putSubject(BCStyle.CN, Rules.fromCsr().optional());
        accumulator.putSubject(BCStyle.O, Rules.fromCsr().optional());
        accumulator.putSanType(GeneralName.dNSName, Rules.fromCsr().optional());
        accumulator.putSanType(GeneralName.iPAddress, Rules.fromCsr().optional());
        accumulator.keyUsageBits = KeyUsage.digitalSignature;
        accumulator.eku = new KeyPurposeId[] { KeyPurposeId.id_kp_clientAuth };
        accumulator.endEntity = true;
        accumulator.setValidity(ValidityRule.fromCsr().optional().orCaller().orDefault(Duration.ofDays(90)));
    }

    public ClientAuthPolicyBuilder commonName(FieldRule rule) {
        accumulator.putSubject(BCStyle.CN, rule);
        return this;
    }

    public ClientAuthPolicyBuilder organization(FieldRule rule) {
        accumulator.putSubject(BCStyle.O, rule);
        return this;
    }

    public ClientAuthPolicyBuilder country(FieldRule rule) {
        accumulator.putSubject(BCStyle.C, rule);
        return this;
    }

    public ClientAuthPolicyBuilder dns(FieldRule rule) {
        accumulator.putSanType(GeneralName.dNSName, rule);
        return this;
    }

    public ClientAuthPolicyBuilder ip(FieldRule rule) {
        accumulator.putSanType(GeneralName.iPAddress, rule);
        return this;
    }

    public ClientAuthPolicyBuilder crl(String uri) {
        accumulator.requireUri(uri, "crl");
        accumulator.crlUris.add(uri);
        return this;
    }

    public ClientAuthPolicyBuilder ocsp(String uri) {
        accumulator.requireUri(uri, "ocsp");
        accumulator.ocspUris.add(uri);
        return this;
    }

    public ClientAuthPolicyBuilder caIssuers(String uri) {
        accumulator.requireUri(uri, "caIssuers");
        accumulator.caIssuersUris.add(uri);
        return this;
    }

    public ClientAuthPolicyBuilder validity(ValidityRule rule) {
        accumulator.setValidity(rule);
        return this;
    }

    public ClientAuthPolicyBuilder validity(Duration duration) {
        accumulator.setValidity(duration);
        return this;
    }

    public ClientAuthPolicyBuilder custom(Consumer<RawPolicy> customizer) {
        customizer.accept(new RawPolicyImpl(accumulator));
        return this;
    }

    public IssuancePolicy build() {
        return new IssuancePolicy(accumulator);
    }
}
