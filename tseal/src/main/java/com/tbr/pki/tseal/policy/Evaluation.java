package com.tbr.pki.tseal.policy;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

final class Evaluation {

    final List<PolicyViolation> violations = new ArrayList<>();
    X500Name subject;
    final List<GeneralName> san = new ArrayList<>();
    Duration validity;
    Integer keyUsageBits;
    Extensions extensions;

    void add(String field, String message) {
        violations.add(new PolicyViolation(field, message));
    }

    boolean ok() {
        return violations.isEmpty();
    }

    KeyUsage keyUsage() {
        return keyUsageBits == null ? null : new KeyUsage(keyUsageBits);
    }
}
