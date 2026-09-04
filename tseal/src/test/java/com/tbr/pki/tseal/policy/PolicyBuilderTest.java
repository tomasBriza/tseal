package com.tbr.pki.tseal.policy;

import com.tbr.pki.tseal.csr.CsrBuilder;
import com.tbr.pki.tseal.csr.CsrResult;
import com.tbr.pki.tseal.key.KeyAlgorithm;
import com.tbr.pki.tseal.key.KeyPairFactory;
import com.tbr.pki.tseal.policy.builder.CustomPolicyBuilder;
import com.tbr.pki.tseal.policy.engine.Evaluation;
import com.tbr.pki.tseal.policy.engine.PolicyEngine;
import com.tbr.pki.tseal.policy.restriction.RestrictionOutcome;

import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Duration;

import static com.tbr.pki.tseal.policy.Rules.exactly;
import static com.tbr.pki.tseal.policy.Rules.forbidden;
import static com.tbr.pki.tseal.policy.Rules.fromCsr;
import static com.tbr.pki.tseal.policy.Rules.ignoreCsr;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PolicyBuilderTest {

    private final KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);

    @Test
    void httpsPolicy_acceptsOwnHttpsCsr() {
        CsrResult csr = CsrBuilder.httpsCsr()
                .commonName("app")
                .dns("app.acme.com")
                .build(kp);

        IssuancePolicy policy = PolicyBuilder.httpsPolicy().build();

        assertDoesNotThrow(() -> policy.check(csr.request()));
        assertDoesNotThrow(() -> policy.check(csr.pem()));
    }

    @Test
    void httpsPolicy_ipOnly_accepted() {
        CsrResult csr = CsrBuilder.httpsCsr()
                .commonName("internal")
                .ip("10.0.0.1")
                .build(kp);

        assertDoesNotThrow(() -> PolicyBuilder.httpsPolicy().build().check(csr.request()));
    }

    @Test
    void httpsPolicy_emailSan_rejected() {
        CsrResult csr = CsrBuilder.custom()
                .subject().commonName("app").and()
                .san().dns("app.acme.com").email("svc@acme.com").and()
                .keyUsage(KeyUsage.digitalSignature)
                .build(kp);

        PolicyViolationException ex = assertThrows(
                PolicyViolationException.class,
                () -> PolicyBuilder.httpsPolicy().build().check(csr.request()));
        assertTrue(ex.violations().stream().anyMatch(v -> v.field().startsWith("unknown.san")));
    }

    @Test
    void httpsPolicy_dnsMatching() {
        CsrResult ok = CsrBuilder.httpsCsr().dns("app.acme.com").build(kp);
        CsrResult bad = CsrBuilder.httpsCsr().dns("app.evil.com").build(kp);
        IssuancePolicy policy = PolicyBuilder.httpsPolicy()
                .dns(fromCsr().matching(".*\\.acme\\.com"))
                .build();

        assertDoesNotThrow(() -> policy.check(ok.request()));
        PolicyViolationException ex = assertThrows(
                PolicyViolationException.class, () -> policy.check(bad.request()));
        assertTrue(ex.violations().stream().anyMatch(v -> v.field().equals("san.dNSName")));
    }

    @Test
    void httpsPolicy_unexpectedOrganization_rejected() {
        CsrResult csr = CsrBuilder.custom()
                .subject().commonName("app").organization("Evil").and()
                .san().dns("app.acme.com").and()
                .build(kp);

        PolicyViolationException ex = assertThrows(
                PolicyViolationException.class,
                () -> PolicyBuilder.httpsPolicy().build().check(csr.request()));
        assertTrue(ex.violations().stream().anyMatch(v -> v.field().startsWith("unknown.subject")));
    }

    @Test
    void httpsPolicy_exactlyOrganization() {
        CsrResult csr = CsrBuilder.httpsCsr().dns("app.acme.com").build(kp);
        IssuancePolicy policy = PolicyBuilder.httpsPolicy()
                .organization(exactly("Acme Corp"))
                .build();

        assertDoesNotThrow(() -> policy.check(csr.request()));
    }

    @Test
    void clientAuthPolicy_acceptsOwnCsr() {
        CsrResult csr = CsrBuilder.clientAuthCsr()
                .commonName("client-app")
                .organization("Acme")
                .build(kp);

        assertDoesNotThrow(() -> PolicyBuilder.clientAuthPolicy().build().check(csr.request()));
    }

    @Test
    void signingPolicy_acceptsOwnCsr() {
        CsrResult csr = CsrBuilder.signingCsr()
                .commonName("Intermediate CA")
                .organization("Acme Corp")
                .build(kp);

        assertDoesNotThrow(() -> PolicyBuilder.signingPolicy().build().check(csr.request()));
    }

    @Test
    void signingPolicy_rejectsSan() {
        CsrResult csr = CsrBuilder.httpsCsr().dns("ca.example.com").build(kp);

        PolicyViolationException ex = assertThrows(
                PolicyViolationException.class,
                () -> PolicyBuilder.signingPolicy().build().check(csr.request()));
        assertTrue(ex.violations().stream().anyMatch(v -> v.field().startsWith("unknown.san")));
    }

    @Test
    void validity_fromCsr() {
        CsrResult csr = CsrBuilder.httpsCsr()
                .dns("app.acme.com")
                .validity(Duration.ofDays(30))
                .build(kp);

        IssuancePolicy policy = PolicyBuilder.httpsPolicy()
                .validity(ValidityRule.fromCsr().max(Duration.ofDays(90)))
                .build();

        assertDoesNotThrow(() -> policy.check(csr.request()));
    }

    @Test
    void validity_aboveMax_rejected() {
        CsrResult csr = CsrBuilder.httpsCsr()
                .dns("app.acme.com")
                .validity(Duration.ofDays(400))
                .build(kp);

        IssuancePolicy policy = PolicyBuilder.httpsPolicy()
                .validity(ValidityRule.fromCsr().orDefault(Duration.ofDays(90)).max(Duration.ofDays(398)))
                .build();

        PolicyViolationException ex = assertThrows(
                PolicyViolationException.class, () -> policy.check(csr.request()));
        assertTrue(ex.violations().stream().anyMatch(v -> v.field().equals("validity")));
    }

    @Test
    void validity_defaultWhenCsrOmits() {
        CsrResult csr = CsrBuilder.httpsCsr().dns("app.acme.com").build(kp);

        assertDoesNotThrow(() -> PolicyBuilder.httpsPolicy().build().check(csr.request()));
    }

    @Test
    void validity_orCaller() {
        CsrResult csr = CsrBuilder.httpsCsr().dns("app.acme.com").build(kp);
        IssuancePolicy policy = PolicyBuilder.httpsPolicy()
                .validity(ValidityRule.fromCsr().orCaller())
                .build();

        assertDoesNotThrow(() -> policy.check(csr.request(), CallerValues.of().validity(Duration.ofDays(14))));
        assertThrows(PolicyViolationException.class, () -> policy.check(csr.request()));
    }

    @Test
    void validity_exactly_ignoresCsrRequest() {
        CsrResult csr = CsrBuilder.httpsCsr()
                .dns("app.acme.com")
                .validity(Duration.ofDays(1))
                .build(kp);

        assertDoesNotThrow(() -> PolicyBuilder.httpsPolicy()
                .validity(Duration.ofDays(90))
                .build()
                .check(csr.request()));
    }

    @Test
    void forbiddenValidity_withoutFallback_rejectedAtBuild() {
        assertThrows(IllegalArgumentException.class,
                () -> PolicyBuilder.httpsPolicy().validity(ValidityRule.forbidden()).build());
    }

    @Test
    void crlAndOcsp_doNotAffectCheck() {
        CsrResult csr = CsrBuilder.httpsCsr().dns("app.acme.com").build(kp);
        IssuancePolicy policy = PolicyBuilder.httpsPolicy()
                .crl("http://crl.acme.com/acme.crl")
                .ocsp("http://ocsp.acme.com")
                .caIssuers("http://ca.acme.com/acme.crt")
                .build();

        assertDoesNotThrow(() -> policy.check(csr.request()));
    }

    @Test
    void blankCrl_rejectedAtBuilder() {
        assertThrows(IllegalArgumentException.class, () -> PolicyBuilder.httpsPolicy().crl("  "));
        assertThrows(IllegalArgumentException.class, () -> PolicyBuilder.httpsPolicy().ocsp(null));
    }

    @Test
    void orCaller_organization() {
        CsrResult csr = CsrBuilder.clientAuthCsr().commonName("svc").build(kp);
        IssuancePolicy policy = PolicyBuilder.clientAuthPolicy()
                .organization(fromCsr().orCaller())
                .build();

        assertThrows(PolicyViolationException.class, () -> policy.check(csr.request()));
        assertDoesNotThrow(() -> policy.check(csr.request(), CallerValues.of().organization("Acme West")));
    }

    @Test
    void caller_addsSan() {
        CsrResult csr = CsrBuilder.httpsCsr().dns("app.acme.com").build(kp);
        IssuancePolicy policy = PolicyBuilder.httpsPolicy()
                .dns(fromCsr().orCaller().matching(".*\\.acme\\.com"))
                .build();

        assertDoesNotThrow(() -> policy.check(csr.request(), CallerValues.of().dns("extra.acme.com")));
        assertThrows(PolicyViolationException.class,
                () -> policy.check(csr.request(), CallerValues.of().dns("evil.com")));
    }

    @Test
    void custom_requiresValidity() {
        assertThrows(IllegalStateException.class, () -> new CustomPolicyBuilder().build());
    }

    @Test
    void custom_endToEnd() {
        CsrResult csr = CsrBuilder.httpsCsr().commonName("app").dns("app.acme.com").build(kp);
        IssuancePolicy policy = PolicyBuilder.custom()
                .subject().commonName(fromCsr().optional()).and()
                .san().dns(fromCsr().required()).ip(fromCsr().optional()).email(forbidden()).and()
                .keyUsage(KeyUsage.digitalSignature)
                .extendedKeyUsage(KeyPurposeId.id_kp_serverAuth)
                .endEntity()
                .crl("http://crl.acme.com/acme.crl")
                .validity(ValidityRule.fromCsr().orDefault(Duration.ofDays(90)))
                .build();

        assertDoesNotThrow(() -> policy.check(csr.request()));
    }

    @Test
    void collectsAllViolations() {
        CsrResult csr = CsrBuilder.custom()
                .subject().commonName("app").organization("X").and()
                .san().dns("nope.example.com").email("a@b.c").and()
                .build(kp);

        PolicyViolationException ex = assertThrows(
                PolicyViolationException.class,
                () -> PolicyBuilder.httpsPolicy()
                        .dns(fromCsr().matching(".*\\.acme\\.com"))
                        .build()
                        .check(csr.request()));
        assertTrue(ex.violations().size() >= 2);
    }

    @Test
    void country_twoLetterDefault() {
        CsrResult csr = CsrBuilder.custom()
                .subject().commonName("app").country("CZE").and()
                .san().dns("app.acme.com").and()
                .build(kp);

        IssuancePolicy policy = PolicyBuilder.httpsPolicy()
                .country(fromCsr())
                .build();

        PolicyViolationException ex = assertThrows(
                PolicyViolationException.class, () -> policy.check(csr.request()));
        assertTrue(ex.violations().stream().anyMatch(v -> v.field().equals("subject.C")));
        assertTrue(ex.violations().stream().anyMatch(v -> ViolationCodes.VALUE_COUNTRY.equals(v.code())));
    }

    @Test
    void dnsMatching_hasStableCode() {
        CsrResult bad = CsrBuilder.httpsCsr().dns("app.evil.com").build(kp);
        PolicyViolationException ex = assertThrows(
                PolicyViolationException.class,
                () -> PolicyBuilder.httpsPolicy().dns(fromCsr().matching(".*\\.acme\\.com")).build()
                        .check(bad.request()));
        assertTrue(ex.violations().stream().anyMatch(v -> ViolationCodes.VALUE_REGEX.equals(v.code())));
    }

    @Test
    void unknownSan_hasStableCode() {
        CsrResult csr = CsrBuilder.custom()
                .subject().commonName("app").and()
                .san().dns("app.acme.com").email("svc@acme.com").and()
                .build(kp);
        PolicyViolationException ex = assertThrows(
                PolicyViolationException.class,
                () -> PolicyBuilder.httpsPolicy().build().check(csr.request()));
        assertTrue(ex.violations().stream().anyMatch(v -> ViolationCodes.SAN_UNKNOWN.equals(v.code())));
    }

    @Test
    void subjectCardinality_defaultMaxOne() {
        CsrResult csr = CsrBuilder.custom()
                .subject().commonName("a").commonName("b").and()
                .san().dns("app.acme.com").and()
                .build(kp);
        PolicyViolationException ex = assertThrows(
                PolicyViolationException.class,
                () -> PolicyBuilder.httpsPolicy().build().check(csr.request()));
        assertTrue(ex.violations().stream().anyMatch(v -> ViolationCodes.SUBJECT_CARDINALITY.equals(v.code())));
    }

    @Test
    void subjectCardinality_maxEntriesTwo() {
        CsrResult csr = CsrBuilder.custom()
                .subject().commonName("a").commonName("b").and()
                .san().dns("app.acme.com").and()
                .build(kp);
        IssuancePolicy policy = PolicyBuilder.httpsPolicy()
                .commonName(fromCsr().optional().maxEntries(2))
                .build();
        assertDoesNotThrow(() -> policy.check(csr.request()));
    }

    @Test
    void lambdaRestriction_enforced() {
        CsrResult ok = CsrBuilder.httpsCsr().dns("app.acme.com").build(kp);
        CsrResult bad = CsrBuilder.httpsCsr().dns("app.evil.com").build(kp);
        IssuancePolicy policy = PolicyBuilder.httpsPolicy()
                .dns(fromCsr().restrict(v -> v.endsWith(".acme.com")
                        ? RestrictionOutcome.allow()
                        : RestrictionOutcome.reject("value.suffix", "must end with .acme.com")))
                .build();
        assertDoesNotThrow(() -> policy.check(ok.request()));
        PolicyViolationException ex = assertThrows(
                PolicyViolationException.class, () -> policy.check(bad.request()));
        assertTrue(ex.violations().stream().anyMatch(v -> "value.suffix".equals(v.code())));
    }

    @Test
    void ignoreCsr_usesCallerThenDefault() {
        CsrResult csr = CsrBuilder.httpsCsr()
                .commonName("from-csr")
                .dns("app.acme.com")
                .build(kp);
        IssuancePolicy policy = PolicyBuilder.httpsPolicy()
                .commonName(ignoreCsr().orCaller().orDefault("fallback"))
                .build();

        assertDoesNotThrow(() -> policy.check(csr.request()));
        Evaluation withDefault = PolicyEngine.evaluate(
                policy.spec, csr.request(), CallerValues.empty());
        assertTrue(withDefault.ok(), withDefault.violations::toString);
        assertTrue(withDefault.subject.toString().contains("fallback"));
        assertTrue(!withDefault.subject.toString().contains("from-csr"));

        Evaluation withCaller = PolicyEngine.evaluate(
                policy.spec, csr.request(), CallerValues.of().commonName("from-caller"));
        assertTrue(withCaller.ok(), withCaller.violations::toString);
        assertTrue(withCaller.subject.toString().contains("from-caller"));
    }

    @Test
    void ignoreCsr_snapshotRoundTrip() {
        IssuancePolicy original = PolicyBuilder.httpsPolicy()
                .organization(ignoreCsr().orCaller().orDefault("Acme"))
                .build();
        IssuancePolicy restored = original.snapshot().toPolicy();
        assertTrue(restored.snapshot().subject().get("O").mode().equals("ignoreCsr"));
        CsrResult csr = CsrBuilder.httpsCsr().dns("app.acme.com").build(kp);
        assertDoesNotThrow(() -> restored.check(csr.request(), CallerValues.of().organization("West")));
    }

    @Test
    void setRdn_cnAndEmail_accepted() throws Exception {
        var name = new org.bouncycastle.asn1.x500.X500Name(new org.bouncycastle.asn1.x500.RDN[] {
                new org.bouncycastle.asn1.x500.RDN(new org.bouncycastle.asn1.x500.AttributeTypeAndValue[] {
                        new org.bouncycastle.asn1.x500.AttributeTypeAndValue(
                                org.bouncycastle.asn1.x500.style.BCStyle.CN,
                                new org.bouncycastle.asn1.DERUTF8String("Jane")),
                        new org.bouncycastle.asn1.x500.AttributeTypeAndValue(
                                org.bouncycastle.asn1.x500.style.BCStyle.E,
                                new org.bouncycastle.asn1.DERUTF8String("jane@acme.com"))
                })
        });
        var builder = new org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder(name, kp.getPublic());
        var signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider(org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME)
                .build(kp.getPrivate());
        var csr = builder.build(signer);

        IssuancePolicy policy = PolicyBuilder.custom()
                .subject()
                    .commonName(fromCsr().optional())
                    .rdn(org.bouncycastle.asn1.x500.style.BCStyle.E, fromCsr().optional().maxEntries(1))
                .and()
                .endEntity()
                .validity(Duration.ofDays(90))
                .build();
        assertDoesNotThrow(() -> policy.check(csr));
    }
}
