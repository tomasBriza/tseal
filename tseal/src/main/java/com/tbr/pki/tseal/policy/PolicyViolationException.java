package com.tbr.pki.tseal.policy;

import java.util.List;
import java.util.stream.Collectors;

public final class PolicyViolationException extends RuntimeException {

    private final List<PolicyViolation> violations;

    public PolicyViolationException(List<PolicyViolation> violations) {
        super(format(violations));
        if (violations == null || violations.isEmpty()) {
            throw new IllegalArgumentException("violations must be non-empty");
        }
        this.violations = List.copyOf(violations);
    }

    public List<PolicyViolation> violations() {
        return violations;
    }

    private static String format(List<PolicyViolation> violations) {
        if (violations == null || violations.isEmpty()) {
            return "policy violation";
        }
        return violations.stream().map(PolicyViolation::toString).collect(Collectors.joining("; "));
    }
}
