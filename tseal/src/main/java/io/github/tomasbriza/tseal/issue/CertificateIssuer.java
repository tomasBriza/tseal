package io.github.tomasbriza.tseal.issue;

import io.github.tomasbriza.tseal.policy.IssuancePolicy;

/**
 * Issues an X.509 certificate from a CSR and an {@link IssuancePolicy}.
 * {@code issue()} returns {@link IssueResult.Issued} or {@link IssueResult.Rejected}.
 */
public final class CertificateIssuer {

    private CertificateIssuer() {}

    public static IssueStart issue() {
        return new CertificateIssueBuilder();
    }
}
