package com.tbr.pki.tseal.csr;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.operator.ContentSigner;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

class CsrAccumulator {

    final X500NameBuilder subjectBuilder = new X500NameBuilder(BCStyle.INSTANCE);
    final List<GeneralName> sanEntries = new ArrayList<>();
    final ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
    final List<CsrAttribute> extraAttributes = new ArrayList<>();

    /** If true, the engine computes KeyUsage from the public key type at build time (HTTPS policy). */
    boolean adaptiveKeyUsage = false;

    String signatureAlgorithmOverride = null;
    ContentSigner contentSignerOverride = null;

    /** Requested lifetime in seconds; null if the CSR does not ask. */
    Duration requestedValidity = null;

    void requestedValidity(Duration duration) {
        if (duration == null || duration.isNegative() || duration.toSeconds() <= 0) {
            throw new IllegalArgumentException("Requested validity must be at least one second");
        }
        this.requestedValidity = duration;
    }

    void addExtension(ASN1ObjectIdentifier oid, boolean critical, ASN1Encodable value) {
        try {
            extensionsGenerator.addExtension(oid, critical, value);
        } catch (IOException e) {
            throw new IllegalArgumentException("Failed to add extension " + oid, e);
        }
    }

    record CsrAttribute(ASN1ObjectIdentifier oid, ASN1Encodable value) {}
}
