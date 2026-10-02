package io.github.tomasbriza.tseal.policy.engine;

import io.github.tomasbriza.tseal.policy.Evaluation;
import io.github.tomasbriza.tseal.policy.PolicyViolation;
import io.github.tomasbriza.tseal.policy.ViolationCodes;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/** Mutable working state for {@link PolicyEngine}. Not a result. */
final class EvaluationDraft {

    final List<PolicyViolation> violations = new ArrayList<>();
    X500Name subject;
    final List<GeneralName> san = new ArrayList<>();
    Duration validity;
    Integer keyUsageBits;
    Extensions extensions;

    void add(String field, String message) {
        add(field, message, ViolationCodes.POLICY);
    }

    void add(String field, String message, String code) {
        violations.add(new PolicyViolation(field, message, code));
    }

    Evaluation finish() {
        if (violations.isEmpty()) {
            return new Evaluation.Ok(subject, san, validity, keyUsageBits, extensions);
        }
        return new Evaluation.Violations(violations);
    }
}
