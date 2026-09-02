package com.tbr.pki.tseal.policy;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public interface RawPolicy {
    RawPolicy addExtension(ASN1ObjectIdentifier oid, boolean critical, ASN1Encodable value);
    RawPolicy copyExtensionFromCsr(ASN1ObjectIdentifier oid, boolean required);
    RawPolicy ignoreCsrExtension(ASN1ObjectIdentifier oid);
    RawPolicy allowSubjectRdn(ASN1ObjectIdentifier oid, FieldRule rule);
    RawPolicy allowSanType(int generalNameTag, FieldRule rule);
}
