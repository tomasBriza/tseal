package io.github.tomasbriza.tseal.policy;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;

import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * Result of {@link IssuancePolicy#check}.
 * {@link Ok} is the certificate fields. {@link Violations} is a policy miss, not an exception.
 */
public sealed interface Evaluation permits Evaluation.Ok, Evaluation.Violations {

    record Ok(
            X500Name subject,
            List<GeneralName> san,
            Duration validity,
            Integer keyUsageBits,
            Extensions extensions) implements Evaluation {

        public Ok {
            Objects.requireNonNull(subject, "subject");
            Objects.requireNonNull(validity, "validity");
            san = san == null ? List.of() : List.copyOf(san);
        }

        public KeyUsage keyUsage() {
            return keyUsageBits == null ? null : new KeyUsage(keyUsageBits);
        }
    }

    record Violations(List<PolicyViolation> violations) implements Evaluation {

        public Violations {
            if (violations == null || violations.isEmpty()) {
                throw new IllegalArgumentException("violations must be non-empty");
            }
            violations = List.copyOf(violations);
        }
    }
}
