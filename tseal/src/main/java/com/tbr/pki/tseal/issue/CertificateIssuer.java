package com.tbr.pki.tseal.issue;

import com.tbr.pki.tseal.policy.IssuancePolicy;

/**
 * Issues an X.509 certificate from a CSR and an {@link IssuancePolicy}.
 * Policy evaluation is internal; the public surface is the type-state builder.
 */
public final class CertificateIssuer {

    private CertificateIssuer() {}

    public static IssueStart issue() {
        return new CertificateIssueBuilder();
    }
}
