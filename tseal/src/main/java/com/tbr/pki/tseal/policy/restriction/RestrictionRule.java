package com.tbr.pki.tseal.policy.restriction;

/**
 * A value check. Single-method so lambdas, method references, and Spring bean
 * methods are all valid: {@code fromCsr().restrict(bean::evaluate)}.
 */
@FunctionalInterface
public interface RestrictionRule {
    RestrictionOutcome evaluate(String value);
}
