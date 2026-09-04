package com.tbr.pki.tseal.policy.builder;

import com.tbr.pki.tseal.policy.FieldRule;
import com.tbr.pki.tseal.policy.engine.PolicyAccumulator;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public class RawPolicyImpl implements RawPolicy {

    private final PolicyAccumulator accumulator;

    public RawPolicyImpl(PolicyAccumulator accumulator) {
        this.accumulator = accumulator;
    }

    @Override
    public RawPolicy addExtension(ASN1ObjectIdentifier oid, boolean critical, ASN1Encodable value) {
        accumulator.extraExtensions.add(new PolicyAccumulator.CaExtension(oid, critical, value));
        return this;
    }

    @Override
    public RawPolicy copyExtensionFromCsr(ASN1ObjectIdentifier oid, boolean required) {
        accumulator.copyFromCsr.put(oid, required);
        return this;
    }

    @Override
    public RawPolicy ignoreCsrExtension(ASN1ObjectIdentifier oid) {
        accumulator.ignoreCsrExtensions.add(oid);
        return this;
    }

    @Override
    public RawPolicy allowSubjectRdn(ASN1ObjectIdentifier oid, FieldRule rule) {
        accumulator.putSubject(oid, rule);
        return this;
    }

    @Override
    public RawPolicy allowSanType(int generalNameTag, FieldRule rule) {
        accumulator.putSanType(generalNameTag, rule);
        return this;
    }
}
