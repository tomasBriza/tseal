package com.tbr.pki.tseal.policy;

import com.tbr.pki.tseal.csr.CsrBuilder;
import com.tbr.pki.tseal.csr.CsrResult;
import com.tbr.pki.tseal.csr.KeyAlgorithm;
import com.tbr.pki.tseal.csr.KeyPairFactory;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Duration;

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
    }

    @Test
    void missingValidity_rejected() {
        PolicySnapshot snapshot = PolicyBuilder.httpsPolicy().build().snapshot();
        PolicySnapshot withoutValidity = new PolicySnapshot(
                snapshot.version(),
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
                2, null, null, null, null, null, null, null, null, null, null, null, null, null, null));
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
}
