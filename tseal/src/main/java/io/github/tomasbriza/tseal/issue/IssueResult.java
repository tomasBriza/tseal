package io.github.tomasbriza.tseal.issue;

import io.github.tomasbriza.tseal.policy.PolicyViolation;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Outcome of {@code issue()}.
 * {@link Issued} is the certificate. {@link Rejected} is a policy miss or an issuance failure
 * (bad CSR signature, non-CA issuer, missing input, signer or encoding failure).
 */
public sealed interface IssueResult permits IssueResult.Issued, IssueResult.Rejected {

    record Issued(X509Certificate certificate, String pem) implements IssueResult {}

    record Rejected(List<PolicyViolation> violations) implements IssueResult {

        public Rejected {
            if (violations == null || violations.isEmpty()) {
                throw new IllegalArgumentException("violations must be non-empty");
            }
            violations = List.copyOf(violations);
        }
    }
}
