package com.tbr.pki.tseal.csr;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.x500.style.BCStyle;

public final class SubjectBuilder<P> {

    private final CsrAccumulator accumulator;
    private final P parent;

    SubjectBuilder(CsrAccumulator accumulator, P parent) {
        this.accumulator = accumulator;
        this.parent = parent;
    }

    public SubjectBuilder<P> commonName(String cn) {
        accumulator.subjectBuilder.addRDN(BCStyle.CN, cn);
        return this;
    }

    public SubjectBuilder<P> organization(String o) {
        accumulator.subjectBuilder.addRDN(BCStyle.O, o);
        return this;
    }

    public SubjectBuilder<P> organizationalUnit(String ou) {
        accumulator.subjectBuilder.addRDN(BCStyle.OU, ou);
        return this;
    }

    public SubjectBuilder<P> country(String c) {
        accumulator.subjectBuilder.addRDN(BCStyle.C, new DERPrintableString(c));
        return this;
    }

    public SubjectBuilder<P> rdn(ASN1ObjectIdentifier oid, ASN1Encodable value) {
        accumulator.subjectBuilder.addRDN(oid, value);
        return this;
    }

    public P and() {
        return parent;
    }
}
