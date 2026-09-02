package com.tbr.pki.tseal.csr;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.operator.ContentSigner;

public interface RawCsr {
    RawCsr addAttribute(ASN1ObjectIdentifier oid, ASN1Encodable value);
    RawCsr addExtension(ASN1ObjectIdentifier oid, boolean critical, ASN1Encodable value);
    RawCsr subjectRdn(ASN1ObjectIdentifier oid, ASN1Encodable value);
    RawCsr signatureAlgorithm(String jcaName);
    RawCsr contentSigner(ContentSigner signer);
}
