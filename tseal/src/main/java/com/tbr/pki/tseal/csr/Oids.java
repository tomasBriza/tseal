package com.tbr.pki.tseal.csr;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * Library-defined OIDs written into CSRs. {@code 2.25} is the UUID arc (ITU-T X.667);
 * the integer is UUID {@code 983fe82b-05a7-555a-bbb6-e1dda2054e60}
 * (name-based, {@code com.tbr.pki.tseal.requested-validity}).
 */
public final class Oids {

    /**
     * Requested certificate lifetime, as a non-critical {@code extensionRequest} extension
     * whose value is an ASN.1 {@code INTEGER} (seconds). Not a pair of timestamps.
     */
    public static final ASN1ObjectIdentifier REQUESTED_VALIDITY =
            new ASN1ObjectIdentifier("2.25.202374478988983660858747592558420250208");

    private Oids() {}
}
