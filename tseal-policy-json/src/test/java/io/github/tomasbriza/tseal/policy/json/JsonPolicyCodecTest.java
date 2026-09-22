package io.github.tomasbriza.tseal.policy.json;

import io.github.tomasbriza.tseal.csr.CsrBuilder;
import io.github.tomasbriza.tseal.csr.CsrResult;
import io.github.tomasbriza.tseal.key.KeyAlgorithm;
import io.github.tomasbriza.tseal.key.KeyPairFactory;
import io.github.tomasbriza.tseal.policy.IssuancePolicy;
import io.github.tomasbriza.tseal.policy.PolicyBuilder;
import io.github.tomasbriza.tseal.policy.ValidityRule;
import io.github.tomasbriza.tseal.policy.restriction.RestrictionOutcome;
import io.github.tomasbriza.tseal.policy.restriction.RestrictionRule;
import io.github.tomasbriza.tseal.policy.restriction.RestrictionRules;
import io.github.tomasbriza.tseal.policy.snapshot.PolicyCodec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Duration;
import java.util.Map;

import static io.github.tomasbriza.tseal.policy.Rules.exactly;
import static io.github.tomasbriza.tseal.policy.Rules.fromCsr;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonPolicyCodecTest {

    private final PolicyCodec json = new JsonPolicyCodec();
    private final KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);

    @Test
    void format_isJson() {
        assertEquals("json", json.format());
    }

    @Test
    void https_roundTrip_checkPasses() {
        CsrResult csr = CsrBuilder.httpsCsr().commonName("app").dns("app.acme.com").build(kp);
        IssuancePolicy original = PolicyBuilder.httpsPolicy().build();

        IssuancePolicy restored = json.read(json.write(original));
        assertDoesNotThrow(() -> restored.check(csr.request()));
        assertEquals(original.snapshot(), restored.snapshot());
    }

    @Test
    void clientAuth_roundTrip() {
        CsrResult csr = CsrBuilder.clientAuthCsr().commonName("client").organization("Acme").build(kp);
        IssuancePolicy restored = json.read(json.write(PolicyBuilder.clientAuthPolicy().build()));
        assertDoesNotThrow(() -> restored.check(csr.request()));
    }

    @Test
    void signing_roundTrip() {
        CsrResult csr = CsrBuilder.signingCsr().commonName("CA").organization("Acme").build(kp);
        IssuancePolicy restored = json.read(json.write(PolicyBuilder.signingPolicy().build()));
        assertDoesNotThrow(() -> restored.check(csr.request()));
    }

    @Test
    void tightenedRules_roundTrip() {
        CsrResult csr = CsrBuilder.httpsCsr().dns("app.acme.com").build(kp);
        IssuancePolicy original = PolicyBuilder.httpsPolicy()
                .organization(exactly("Acme Corp"))
                .dns(fromCsr().matching(".*\\.acme\\.com").maxEntries(5))
                .crl("http://crl.acme.com/acme.crl")
                .ocsp("http://ocsp.acme.com")
                .caIssuers("http://ca.acme.com/acme.crt")
                .validity(ValidityRule.fromCsr()
                        .orCaller()
                        .orDefault(Duration.ofDays(90))
                        .min(Duration.ofDays(1))
                        .max(Duration.ofDays(398)))
                .build();

        String text = json.write(original);
        assertTrue(text.contains("fromCsr"));
        assertTrue(text.contains("dns"));
        assertTrue(text.contains("P90D"));
        assertTrue(text.contains("P398D"));
        assertTrue(text.contains("http://crl.acme.com/acme.crl"));

        IssuancePolicy restored = json.read(text);
        assertDoesNotThrow(() -> restored.check(csr.request()));
        assertEquals(original.snapshot(), restored.snapshot());
    }

    @Test
    void custom_withExtraExtension_roundTrip() {
        CsrResult csr = CsrBuilder.httpsCsr().dns("app.acme.com").build(kp);
        var oid = new ASN1ObjectIdentifier("1.2.3.4.5");
        IssuancePolicy original = PolicyBuilder.custom()
                .subject().commonName(fromCsr().optional()).and()
                .san().dns(fromCsr()).and()
                .keyUsage(KeyUsage.digitalSignature)
                .extendedKeyUsage(KeyPurposeId.id_kp_serverAuth)
                .endEntity()
                .custom(raw -> raw.addExtension(oid, false, new DERPrintableString("x")))
                .validity(Duration.ofDays(90))
                .build();

        IssuancePolicy restored = json.read(json.write(original));
        assertDoesNotThrow(() -> restored.check(csr.request()));
        assertEquals(1, restored.snapshot().extraExtensions().size());
        assertEquals(oid.getId(), restored.snapshot().extraExtensions().getFirst().oid());
        assertEquals(original.snapshot(), restored.snapshot());
    }

    @Test
    void writeAndReadPath(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("policy.json");
        IssuancePolicy original = PolicyBuilder.httpsPolicy().build();
        JsonPolicyCodec codec = new JsonPolicyCodec();
        codec.write(original, file);
        IssuancePolicy restored = codec.read(file);
        assertEquals(original.snapshot(), restored.snapshot());
    }

    @Test
    void missingValidity_rejected() {
        String jsonDoc = """
                {
                  "version": 1,
                  "subject": { "CN": { "mode": "fromCsr", "optional": true } },
                  "san": { "dns": { "mode": "fromCsr" } }
                }
                """;
        assertThrows(IllegalArgumentException.class, () -> json.read(jsonDoc));
    }

    @Test
    void unknownVersion_rejected() {
        String jsonDoc = """
                { "version": 3, "validity": { "mode": "exactly", "exact": "P90D" } }
                """;
        assertThrows(IllegalArgumentException.class, () -> json.read(jsonDoc));
    }

    @Test
    void version1_matchingStillLoads() {
        String jsonDoc = """
                {
                  "version": 1,
                  "subject": { "CN": { "mode": "fromCsr", "optional": true } },
                  "san": { "dns": { "mode": "fromCsr", "optional": true, "matching": ".*\\\\.acme\\\\.com" } },
                  "atLeastOneSan": true,
                  "validity": { "mode": "exactly", "exact": "P90D" },
                  "keyUsage": { "adaptive": true },
                  "basicConstraints": { "endEntity": true }
                }
                """;
        IssuancePolicy policy = json.read(jsonDoc);
        CsrResult ok = CsrBuilder.httpsCsr().dns("app.acme.com").build(kp);
        CsrResult bad = CsrBuilder.httpsCsr().dns("app.evil.com").build(kp);
        assertDoesNotThrow(() -> policy.check(ok.request()));
        assertThrows(Exception.class, () -> policy.check(bad.request()));
    }

    @Test
    void registeredRestriction_roundTrip() {
        RestrictionRule endsAcme = v -> v != null && v.endsWith(".acme.com")
                ? RestrictionOutcome.allow()
                : RestrictionOutcome.reject("value.suffix", "must end with .acme.com");
        RestrictionRules.register("endsAcme", endsAcme);
        try {
            IssuancePolicy original = PolicyBuilder.httpsPolicy()
                    .dns(fromCsr().restrict(RestrictionRules.create("endsAcme", Map.of())))
                    .build();
            IssuancePolicy restored = json.read(json.write(original));
            CsrResult ok = CsrBuilder.httpsCsr().dns("app.acme.com").build(kp);
            CsrResult bad = CsrBuilder.httpsCsr().dns("nope.example.com").build(kp);
            assertDoesNotThrow(() -> restored.check(ok.request()));
            assertThrows(Exception.class, () -> restored.check(bad.request()));
            assertEquals("endsAcme", restored.snapshot().san().get("dns").restrictions().getFirst().type());
        } finally {
            RestrictionRules.unregister("endsAcme");
        }
    }

    @Test
    void extends_mergesSubjectOverlay() {
        JsonPolicyCodec codec = new JsonPolicyCodec();
        String base = codec.write(PolicyBuilder.httpsPolicy().build());
        String overlay = """
                {
                  "version": 2,
                  "extends": "base",
                  "subject": { "O": { "mode": "exactly", "exact": "Acme West" } }
                }
                """;
        IssuancePolicy policy = codec.read(overlay, id -> base);
        assertEquals("Acme West", policy.snapshot().subject().get("O").exact());
        assertTrue(policy.snapshot().san().containsKey("dns"));
        CsrResult csr = CsrBuilder.httpsCsr().dns("app.acme.com").build(kp);
        assertDoesNotThrow(() -> policy.check(csr.request()));
    }

    @Test
    void extends_withoutResolver_rejected() {
        String overlay = """
                { "version": 2, "extends": "base", "validity": { "mode": "exactly", "exact": "P90D" } }
                """;
        assertThrows(IllegalArgumentException.class, () -> json.read(overlay));
    }

    @Test
    void blankAndInvalidJson_rejected() {
        assertThrows(IllegalArgumentException.class, () -> json.read(" "));
        assertThrows(IllegalArgumentException.class, () -> json.read("{"));
    }
}
