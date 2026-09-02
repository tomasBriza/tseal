package com.tbr.pki.tseal.policy;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.style.BCStyle;

public final class SubjectRuleBuilder<P> {

    private final PolicyAccumulator accumulator;
    private final P parent;

    SubjectRuleBuilder(PolicyAccumulator accumulator, P parent) {
        this.accumulator = accumulator;
        this.parent = parent;
    }

    public SubjectRuleBuilder<P> commonName(FieldRule rule) {
        accumulator.putSubject(BCStyle.CN, rule);
        return this;
    }

    public SubjectRuleBuilder<P> organization(FieldRule rule) {
        accumulator.putSubject(BCStyle.O, rule);
        return this;
    }

    public SubjectRuleBuilder<P> organizationalUnit(FieldRule rule) {
        accumulator.putSubject(BCStyle.OU, rule);
        return this;
    }

    public SubjectRuleBuilder<P> country(FieldRule rule) {
        accumulator.putSubject(BCStyle.C, rule);
        return this;
    }

    public SubjectRuleBuilder<P> rdn(ASN1ObjectIdentifier oid, FieldRule rule) {
        accumulator.putSubject(oid, rule);
        return this;
    }

    public P and() {
        return parent;
    }
}
