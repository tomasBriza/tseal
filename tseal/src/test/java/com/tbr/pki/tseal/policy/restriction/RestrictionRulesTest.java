package com.tbr.pki.tseal.policy.restriction;

import com.tbr.pki.tseal.csr.CsrBuilder;
import com.tbr.pki.tseal.key.KeyAlgorithm;
import com.tbr.pki.tseal.key.KeyPairFactory;
import com.tbr.pki.tseal.policy.IssuancePolicy;
import com.tbr.pki.tseal.policy.PolicyBuilder;
import com.tbr.pki.tseal.policy.PolicyViolationException;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;

import static com.tbr.pki.tseal.policy.Rules.fromCsr;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RestrictionRulesTest {

    private final KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);

    @AfterEach
    void restoreBuiltins() {
        RestrictionRules.reset();
    }

    /** Mimics a Spring bean with a boolean method. */
    static final class DnsAllowlist {
        boolean isAllowed(String dns) {
            return dns != null && dns.endsWith(".acme.com");
        }
    }

    @Test
    void bindPredicate_springBooleanMethod() {
        var checker = new DnsAllowlist();
        RestrictionRules.builtin()
                .bind("acmeDns", checker::isAllowed, "value.acmeDns", "DNS not allowed");

        IssuancePolicy policy = PolicyBuilder.httpsPolicy()
                .dns(fromCsr().restrict("acmeDns"))
                .build();

        assertDoesNotThrow(() -> policy.check(
                CsrBuilder.httpsCsr().dns("app.acme.com").build(kp).request()));
        PolicyViolationException ex = assertThrows(
                PolicyViolationException.class,
                () -> policy.check(CsrBuilder.httpsCsr().dns("nope.example.com").build(kp).request()));
        assertTrue(ex.violations().stream().anyMatch(v -> "value.acmeDns".equals(v.code())));
    }

    @Test
    void bindRestrictionOutcome_methodReference() {
        RestrictionRules.builtin()
                .bind("suffix", RestrictionRulesTest::acmeSuffix);

        IssuancePolicy policy = PolicyBuilder.httpsPolicy()
                .dns(fromCsr().restrict("suffix"))
                .build();
        assertDoesNotThrow(() -> policy.check(
                CsrBuilder.httpsCsr().dns("x.acme.com").build(kp).request()));
        assertThrows(PolicyViolationException.class, () -> policy.check(
                CsrBuilder.httpsCsr().dns("x.example.com").build(kp).request()));
    }

    @Test
    void snapshot_roundTripNamedBinding() {
        RestrictionRules.builtin()
                .bind("acmeDns", new DnsAllowlist()::isAllowed);
        IssuancePolicy original = PolicyBuilder.httpsPolicy()
                .dns(fromCsr().restrict("acmeDns"))
                .build();
        IssuancePolicy restored = original.snapshot().toPolicy();
        assertDoesNotThrow(() -> restored.check(
                CsrBuilder.httpsCsr().dns("app.acme.com").build(kp).request()));
        assertThrows(PolicyViolationException.class, () -> restored.check(
                CsrBuilder.httpsCsr().dns("nope.example.com").build(kp).request()));
    }

    static RestrictionOutcome acmeSuffix(String dns) {
        return dns != null && dns.endsWith(".acme.com")
                ? RestrictionOutcome.allow()
                : RestrictionOutcome.reject("value.suffix", "must end with .acme.com");
    }
}
