package com.tbr.pki.tseal.issue;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * Escape hatch used from {@code customize}. Policy extensions are already present;
 * SKI and AKI are added after this callback. Duplicate OIDs fail loudly.
 */
public interface RawIssuedCertificate {
    RawIssuedCertificate addExtension(ASN1ObjectIdentifier oid, boolean critical, ASN1Encodable value);
}
