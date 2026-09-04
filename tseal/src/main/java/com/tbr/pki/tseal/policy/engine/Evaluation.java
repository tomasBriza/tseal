package com.tbr.pki.tseal.policy.engine;

import com.tbr.pki.tseal.policy.PolicyViolation;
import com.tbr.pki.tseal.policy.ViolationCodes;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

public final class Evaluation {

    public final List<PolicyViolation> violations = new ArrayList<>();
    public X500Name subject;
    public final List<GeneralName> san = new ArrayList<>();
    public Duration validity;
    public Integer keyUsageBits;
    public Extensions extensions;

    public void add(String field, String message) {
        add(field, message, ViolationCodes.POLICY);
    }

    public void add(String field, String message, String code) {
        violations.add(new PolicyViolation(field, message, code));
    }

    public boolean ok() {
        return violations.isEmpty();
    }

    public KeyUsage keyUsage() {
        return keyUsageBits == null ? null : new KeyUsage(keyUsageBits);
    }
}
