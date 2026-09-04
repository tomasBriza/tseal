package com.tbr.pki.tseal.policy.snapshot;

import com.tbr.pki.tseal.csr.CsrBuilder;
import com.tbr.pki.tseal.csr.CsrResult;
import com.tbr.pki.tseal.key.KeyAlgorithm;
import com.tbr.pki.tseal.key.KeyPairFactory;
import com.tbr.pki.tseal.policy.IssuancePolicy;
import com.tbr.pki.tseal.policy.PolicyBuilder;
import com.tbr.pki.tseal.policy.ValidityRule;
import com.tbr.pki.tseal.policy.restriction.RestrictionOutcome;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Duration;

import static com.tbr.pki.tseal.policy.Rules.exactly;
import static com.tbr.pki.tseal.policy.Rules.fromCsr;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PolicySnapshotTest {

    private final KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);

    @Test
    void https_roundTrip_checkStillPasses() {
        CsrResult csr = CsrBuilder.httpsCsr().dns("app.acme.com").build(kp);
        IssuancePolicy original = PolicyBuilder.httpsPolicy()
                .dns(fromCsr().matching(".*\\.acme\\.com"))
                .crl("http://crl.acme.com/acme.crl")
                .ocsp("http://ocsp.acme.com")
                .validity(ValidityRule.fromCsr().orCaller().orDefault(Duration.ofDays(90)).max(Duration.ofDays(398)))
                .build();

        IssuancePolicy restored = original.snapshot().toPolicy();
        assertDoesNotThrow(() -> restored.check(csr.request()));
        assertEquals(original.snapshot(), restored.snapshot());
        assertEquals(PolicySnapshot.SCHEMA_VERSION, original.snapshot().version());
    }

    @Test
    void missingValidity_rejected() {
        PolicySnapshot snapshot = PolicyBuilder.httpsPolicy().build().snapshot();
        PolicySnapshot withoutValidity = new PolicySnapshot(
                snapshot.version(),
                snapshot.extendsFrom(),
                snapshot.subject(),
                snapshot.san(),
                snapshot.otherNames(),
                snapshot.atLeastOneSan(),
                null,
                snapshot.keyUsage(),
                snapshot.extendedKeyUsage(),
                snapshot.basicConstraints(),
                snapshot.crl(),
                snapshot.ocsp(),
                snapshot.caIssuers(),
                snapshot.extraExtensions(),
                snapshot.copyFromCsr(),
                snapshot.ignoreFromCsr());
        assertThrows(IllegalArgumentException.class, withoutValidity::toPolicy);
    }

    @Test
    void unknownVersion_rejected() {
        assertThrows(IllegalArgumentException.class, () -> new PolicySnapshot(
                3, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null));
    }

    @Test
    void version1_accepted() {
        PolicySnapshot v2 = PolicyBuilder.httpsPolicy().build().snapshot();
        PolicySnapshot v1 = new PolicySnapshot(
                1,
                v2.extendsFrom(),
                v2.subject(),
                v2.san(),
                v2.otherNames(),
                v2.atLeastOneSan(),
                v2.validity(),
                v2.keyUsage(),
                v2.extendedKeyUsage(),
                v2.basicConstraints(),
                v2.crl(),
                v2.ocsp(),
                v2.caIssuers(),
                v2.extraExtensions(),
                v2.copyFromCsr(),
                v2.ignoreFromCsr());
        assertEquals(1, v1.version());
        assertDoesNotThrow(v1::toPolicy);
    }

    @Test
    void defaultHttpsSnapshot_hasValidityAndSan() {
        PolicySnapshot snap = PolicyBuilder.httpsPolicy().build().snapshot();
        assertEquals("fromCsr", snap.validity().mode());
        assertEquals("P90D", snap.validity().orDefault());
        assertTrue(snap.san().containsKey("dns"));
        assertTrue(Boolean.TRUE.equals(snap.atLeastOneSan()));
        assertTrue(Boolean.TRUE.equals(snap.keyUsage().adaptive()));
    }

    @Test
    void merge_overlaySubjectKey() {
        PolicySnapshot base = PolicyBuilder.httpsPolicy().build().snapshot();
        PolicySnapshot overlay = PolicyBuilder.httpsPolicy()
                .organization(exactly("Acme West"))
                .build()
                .snapshot();
        IssuancePolicy merged = base.merge(overlay).toPolicy();
        CsrResult csr = CsrBuilder.httpsCsr().dns("app.acme.com").build(kp);
        assertDoesNotThrow(() -> merged.check(csr.request()));
        assertEquals("exactly", merged.snapshot().subject().get("O").mode());
        assertEquals("Acme West", merged.snapshot().subject().get("O").exact());
        assertTrue(merged.snapshot().san().containsKey("dns"));
    }

    @Test
    void anonymousRestriction_cannotSnapshot() {
        IssuancePolicy policy = PolicyBuilder.httpsPolicy()
                .dns(fromCsr().restrict(v -> RestrictionOutcome.allow()))
                .build();
        assertThrows(IllegalArgumentException.class, policy::snapshot);
    }
}
