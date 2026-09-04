package com.tbr.pki.tseal.policy.builder;

import com.tbr.pki.tseal.policy.FieldRule;
import com.tbr.pki.tseal.policy.engine.PolicyAccumulator;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;

public final class SanRuleBuilder<P> {

    private final PolicyAccumulator accumulator;
    private final P parent;

    public SanRuleBuilder(PolicyAccumulator accumulator, P parent) {
        this.accumulator = accumulator;
        this.parent = parent;
    }

    public SanRuleBuilder<P> dns(FieldRule rule) {
        accumulator.putSanType(GeneralName.dNSName, rule);
        return this;
    }

    public SanRuleBuilder<P> ip(FieldRule rule) {
        accumulator.putSanType(GeneralName.iPAddress, rule);
        return this;
    }

    public SanRuleBuilder<P> email(FieldRule rule) {
        accumulator.putSanType(GeneralName.rfc822Name, rule);
        return this;
    }

    public SanRuleBuilder<P> otherName(ASN1ObjectIdentifier typeId, FieldRule rule) {
        accumulator.putOtherName(typeId, rule);
        return this;
    }

    public P and() {
        return parent;
    }
}
