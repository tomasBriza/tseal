package com.tbr.pki.tseal.csr.builder;

import com.tbr.pki.tseal.csr.engine.CsrAccumulator;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.OtherName;

public final class SanBuilder<P> {

    private final CsrAccumulator accumulator;
    private final P parent;

    public SanBuilder(CsrAccumulator accumulator, P parent) {
        this.accumulator = accumulator;
        this.parent = parent;
    }

    public SanBuilder<P> dns(String dnsName) {
        accumulator.sanEntries.add(new GeneralName(GeneralName.dNSName, dnsName));
        return this;
    }

    public SanBuilder<P> ip(String ipAddress) {
        accumulator.sanEntries.add(new GeneralName(GeneralName.iPAddress, ipAddress));
        return this;
    }

    public SanBuilder<P> email(String emailAddress) {
        accumulator.sanEntries.add(new GeneralName(GeneralName.rfc822Name, emailAddress));
        return this;
    }

    public SanBuilder<P> otherName(ASN1ObjectIdentifier typeId, ASN1Encodable value) {
        accumulator.sanEntries.add(new GeneralName(GeneralName.otherName, new OtherName(typeId, value)));
        return this;
    }

    public P and() {
        return parent;
    }
}
