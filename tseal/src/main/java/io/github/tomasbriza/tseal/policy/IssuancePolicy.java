package io.github.tomasbriza.tseal.policy;

import io.github.tomasbriza.tseal.policy.engine.CsrView;
import io.github.tomasbriza.tseal.policy.engine.PolicyAccumulator;
import io.github.tomasbriza.tseal.policy.engine.PolicyEngine;
import io.github.tomasbriza.tseal.policy.snapshot.PolicySnapshot;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.util.Objects;

public final class IssuancePolicy {

    final PolicyAccumulator spec;

    public IssuancePolicy(PolicyAccumulator spec) {
        if (spec.validity == null) {
            throw new IllegalStateException("validity rule is required");
        }
        spec.validity.validateStatically();
        this.spec = spec;
    }

    /** {@link Evaluation.Ok} or {@link Evaluation.Violations}. A policy miss does not throw. */
    public Evaluation check(PKCS10CertificationRequest csr) {
        return check(csr, CallerValues.empty());
    }

    public Evaluation check(PKCS10CertificationRequest csr, CallerValues caller) {
        return PolicyEngine.evaluate(spec, csr, caller == null ? CallerValues.empty() : caller);
    }

    public Evaluation check(String pem) {
        return check(pem, CallerValues.empty());
    }

    public Evaluation check(String pem, CallerValues caller) {
        return PolicyEngine.evaluate(spec, CsrView.parsePem(pem), caller == null ? CallerValues.empty() : caller);
    }

    /** Format-agnostic interchange for codecs (JSON, …). */
    public PolicySnapshot snapshot() {
        return PolicySnapshot.from(spec);
    }

    public static IssuancePolicy fromSnapshot(PolicySnapshot snapshot) {
        return Objects.requireNonNull(snapshot, "snapshot").toPolicy();
    }

    public IssuancePolicy overlay(PolicySnapshot overlay) {
        return snapshot().merge(overlay).toPolicy();
    }
}
