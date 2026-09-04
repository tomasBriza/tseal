package com.tbr.pki.tseal.csr.engine;

import com.tbr.pki.tseal.csr.RawCsr;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.operator.ContentSigner;

public class RawCsrImpl implements RawCsr {

    private final CsrAccumulator accumulator;

    public RawCsrImpl(CsrAccumulator accumulator) {
        this.accumulator = accumulator;
    }

    @Override
    public RawCsr addAttribute(ASN1ObjectIdentifier oid, ASN1Encodable value) {
        accumulator.extraAttributes.add(new CsrAccumulator.CsrAttribute(oid, value));
        return this;
    }

    @Override
    public RawCsr addExtension(ASN1ObjectIdentifier oid, boolean critical, ASN1Encodable value) {
        accumulator.addExtension(oid, critical, value);
        return this;
    }

    @Override
    public RawCsr subjectRdn(ASN1ObjectIdentifier oid, ASN1Encodable value) {
        accumulator.subjectBuilder.addRDN(oid, value);
        return this;
    }

    @Override
    public RawCsr signatureAlgorithm(String jcaName) {
        accumulator.signatureAlgorithmOverride = jcaName;
        return this;
    }

    @Override
    public RawCsr contentSigner(ContentSigner signer) {
        accumulator.contentSignerOverride = signer;
        return this;
    }
}
