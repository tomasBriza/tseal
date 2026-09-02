package com.tbr.pki.tseal.policy;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.util.Objects;

public final class IssuancePolicy {

    final PolicyAccumulator spec;

    IssuancePolicy(PolicyAccumulator spec) {
        if (spec.validity == null) {
            throw new IllegalStateException("validity rule is required");
        }
        spec.validity.validateStatically();
        this.spec = spec;
    }

    public void check(PKCS10CertificationRequest csr) {
        check(csr, CallerValues.empty());
    }

    public void check(PKCS10CertificationRequest csr, CallerValues caller) {
        PolicyEngine.check(spec, csr, caller);
    }

    public void check(String pem) {
        check(pem, CallerValues.empty());
    }

    public void check(String pem, CallerValues caller) {
        PolicyEngine.check(spec, CsrView.parsePem(pem), caller);
    }

    /** Format-agnostic interchange for codecs (JSON, …). */
    public PolicySnapshot snapshot() {
        return PolicySnapshot.from(this);
    }

    public static IssuancePolicy fromSnapshot(PolicySnapshot snapshot) {
        return Objects.requireNonNull(snapshot, "snapshot").toPolicy();
    }
}
