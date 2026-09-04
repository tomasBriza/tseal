package com.tbr.pki.tseal.issue;

import com.tbr.pki.tseal.csr.CsrBuilder;
import com.tbr.pki.tseal.csr.CsrResult;
import com.tbr.pki.tseal.key.KeyAlgorithm;
import com.tbr.pki.tseal.key.KeyPairFactory;
import com.tbr.pki.tseal.policy.CallerValues;
import com.tbr.pki.tseal.policy.IssuancePolicy;
import com.tbr.pki.tseal.policy.PolicyBuilder;
import com.tbr.pki.tseal.policy.PolicyViolationException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collection;
import java.util.List;

import static com.tbr.pki.tseal.policy.Rules.fromCsr;
import static com.tbr.pki.tseal.policy.Rules.ignoreCsr;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CertificateIssuerTest {

    private final KeyPair caKeys = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
    private final KeyPair leafKeys = KeyPairFactory.generate(KeyAlgorithm.EC_P256);

    @Test
    void selfSignedCa_thenHttpsLeaf() throws Exception {
        IssuedCertificate ca = issueCa();
        assertTrue(ca.certificate().getBasicConstraints() >= 0);
        assertTrue(ca.pem().contains("BEGIN CERTIFICATE"));

        CsrResult csr = CsrBuilder.httpsCsr()
                .commonName("app")
                .dns("app.acme.com")
                .build(leafKeys);
        IssuancePolicy policy = PolicyBuilder.httpsPolicy()
                .crl("http://crl.acme.com/acme.crl")
                .build();

        IssuedCertificate leaf = CertificateIssuer.issue()
                .csr(csr.request())
                .policy(policy)
                .using(ca.certificate(), caKeys.getPrivate())
                .issue();

        leaf.certificate().verify(ca.certificate().getPublicKey());
        assertArrayEquals(leafKeys.getPublic().getEncoded(), leaf.certificate().getPublicKey().getEncoded());
        assertTrue(leaf.certificate().getSubjectX500Principal().getName().contains("app"));
        assertTrue(hasDnsSan(leaf.certificate(), "app.acme.com"));
        assertNotNull(leaf.certificate().getExtensionValue(Extension.subjectKeyIdentifier.getId()));
        assertNotNull(leaf.certificate().getExtensionValue(Extension.authorityKeyIdentifier.getId()));
        assertNotNull(leaf.certificate().getExtensionValue(Extension.cRLDistributionPoints.getId()));
        assertFalse(leaf.certificate().getBasicConstraints() >= 0);
        assertTrue(leaf.certificate().getKeyUsage()[0]); // digitalSignature
        assertTrue(leaf.pem().contains("BEGIN CERTIFICATE"));
    }

    @Test
    void pemCsr_accepted() throws Exception {
        IssuedCertificate ca = issueCa();
        CsrResult csr = CsrBuilder.httpsCsr().dns("app.acme.com").build(leafKeys);
        IssuedCertificate leaf = CertificateIssuer.issue()
                .csr(csr.pem())
                .policy(PolicyBuilder.httpsPolicy().build())
                .using(ca.certificate(), caKeys)
                .issue();
        leaf.certificate().verify(ca.certificate().getPublicKey());
    }

    @Test
    void policyViolation_doesNotIssue() {
        IssuedCertificate ca = issueCa();
        CsrResult csr = CsrBuilder.httpsCsr().dns("app.evil.com").build(leafKeys);
        assertThrows(PolicyViolationException.class, () -> CertificateIssuer.issue()
                .csr(csr.request())
                .policy(PolicyBuilder.httpsPolicy().dns(fromCsr().matching(".*\\.acme\\.com")).build())
                .using(ca.certificate(), caKeys.getPrivate())
                .issue());
    }

    @Test
    void mismatchedCsrSignature_rejected() throws Exception {
        IssuedCertificate ca = issueCa();
        ContentSigner wrong = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(caKeys.getPrivate());
        var csr = CsrBuilder.httpsCsr()
                .dns("app.acme.com")
                .build(leafKeys.getPublic(), wrong);
        assertThrows(IllegalArgumentException.class, () -> CertificateIssuer.issue()
                .csr(csr.request())
                .policy(PolicyBuilder.httpsPolicy().build())
                .using(ca.certificate(), caKeys.getPrivate())
                .issue());
    }

    @Test
    void contentSigner_path() throws Exception {
        IssuedCertificate ca = issueCa();
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(caKeys.getPrivate());
        CsrResult csr = CsrBuilder.httpsCsr().dns("app.acme.com").build(leafKeys);
        IssuedCertificate leaf = CertificateIssuer.issue()
                .csr(csr.request())
                .policy(PolicyBuilder.httpsPolicy().build())
                .using(ca.certificate(), signer)
                .issue();
        leaf.certificate().verify(ca.certificate().getPublicKey());
    }

    @Test
    void ignoreCsr_callerOrganization() throws Exception {
        IssuedCertificate ca = issueCa();
        CsrResult csr = CsrBuilder.httpsCsr().commonName("app").dns("app.acme.com").build(leafKeys);
        IssuedCertificate leaf = CertificateIssuer.issue()
                .csr(csr.request())
                .policy(PolicyBuilder.httpsPolicy()
                        .organization(ignoreCsr().orCaller().orDefault("Acme"))
                        .build())
                .using(ca.certificate(), caKeys.getPrivate())
                .caller(CallerValues.of().organization("West"))
                .issue();
        assertTrue(leaf.certificate().getSubjectX500Principal().toString().contains("West"));
    }

    @Test
    void customize_addsCallerConditionalExtension() throws Exception {
        IssuedCertificate ca = issueCa();
        var oid = new ASN1ObjectIdentifier("1.2.3.4.1");
        CsrResult csr = CsrBuilder.httpsCsr().dns("app.acme.com").build(leafKeys);
        IssuedCertificate leaf = CertificateIssuer.issue()
                .csr(csr.request())
                .policy(PolicyBuilder.httpsPolicy().build())
                .using(ca.certificate(), caKeys.getPrivate())
                .caller(CallerValues.of().attr("note", "west-tenant"))
                .customize((caller, raw) -> {
                    if (caller.attr("note") != null) {
                        raw.addExtension(oid, false, new DERUTF8String(caller.attr("note")));
                    }
                })
                .issue();
        assertNotNull(leaf.certificate().getExtensionValue(oid.getId()));
    }

    @Test
    void customize_duplicatePolicyOid_fails() {
        IssuedCertificate ca = issueCa();
        CsrResult csr = CsrBuilder.httpsCsr().dns("app.acme.com").build(leafKeys);
        assertThrows(IllegalArgumentException.class, () -> CertificateIssuer.issue()
                .csr(csr.request())
                .policy(PolicyBuilder.httpsPolicy().crl("http://crl.acme.com/acme.crl").build())
                .using(ca.certificate(), caKeys.getPrivate())
                .customize((caller, raw) -> raw.addExtension(
                        Extension.cRLDistributionPoints, false, new DERUTF8String("nope")))
                .issue());
    }

    @Test
    void endEntityIssuer_rejected() {
        IssuedCertificate ca = issueCa();
        CsrResult leafCsr = CsrBuilder.httpsCsr().dns("a.acme.com").build(leafKeys);
        IssuedCertificate leaf = CertificateIssuer.issue()
                .csr(leafCsr.request())
                .policy(PolicyBuilder.httpsPolicy().build())
                .using(ca.certificate(), caKeys.getPrivate())
                .issue();
        KeyPair other = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        CsrResult otherCsr = CsrBuilder.httpsCsr().dns("b.acme.com").build(other);
        assertThrows(IllegalArgumentException.class, () -> CertificateIssuer.issue()
                .csr(otherCsr.request())
                .policy(PolicyBuilder.httpsPolicy().build())
                .using(leaf.certificate(), leafKeys.getPrivate())
                .issue());
    }

    @Test
    void clockAndSerial_honoured() throws Exception {
        IssuedCertificate ca = issueCa();
        Instant now = Instant.parse("2026-01-15T12:00:00Z");
        CsrResult csr = CsrBuilder.httpsCsr().dns("app.acme.com").build(leafKeys);
        IssuedCertificate leaf = CertificateIssuer.issue()
                .csr(csr.request())
                .policy(PolicyBuilder.httpsPolicy().build())
                .using(ca.certificate(), caKeys.getPrivate())
                .clock(Clock.fixed(now, ZoneOffset.UTC))
                .backdate(Duration.ZERO)
                .serial(BigInteger.valueOf(42))
                .issue();
        assertEquals(BigInteger.valueOf(42), leaf.certificate().getSerialNumber());
        assertEquals(now, leaf.certificate().getNotBefore().toInstant());
        assertEquals(now.plus(Duration.ofDays(90)), leaf.certificate().getNotAfter().toInstant());
    }

    @Test
    void defaultBackdate_isFiveMinutes() throws Exception {
        IssuedCertificate ca = issueCa();
        Instant now = Instant.parse("2026-01-15T12:00:00Z");
        CsrResult csr = CsrBuilder.httpsCsr().dns("app.acme.com").build(leafKeys);
        IssuedCertificate leaf = CertificateIssuer.issue()
                .csr(csr.request())
                .policy(PolicyBuilder.httpsPolicy().build())
                .using(ca.certificate(), caKeys.getPrivate())
                .clock(Clock.fixed(now, ZoneOffset.UTC))
                .issue();
        assertEquals(now.minus(Duration.ofMinutes(5)), leaf.certificate().getNotBefore().toInstant());
    }

    @Test
    void root_intermediate_leaf_chain() throws Exception {
        KeyPair intKeys = KeyPairFactory.generate(KeyAlgorithm.EC_P256);

        IssuedCertificate root = CertificateIssuer.issue()
                .csr(CsrBuilder.signingCsr().commonName("Acme Root").build(caKeys).request())
                .policy(PolicyBuilder.signingPolicy().unboundedPathLen().build())
                .selfSigned(caKeys)
                .issue();
        assertTrue(root.certificate().getBasicConstraints() >= 0);

        IssuedCertificate intermediate = CertificateIssuer.issue()
                .csr(CsrBuilder.signingCsr().commonName("Acme Intermediate").build(intKeys).request())
                .policy(PolicyBuilder.signingPolicy().pathLen(0).build())
                .using(root.certificate(), caKeys.getPrivate())
                .issue();

        intermediate.certificate().verify(root.certificate().getPublicKey());
        assertTrue(intermediate.certificate().getBasicConstraints() >= 0);
        assertEquals(0, intermediate.certificate().getBasicConstraints());
        assertFalse(intermediate.certificate().getIssuerX500Principal().equals(
                intermediate.certificate().getSubjectX500Principal()));
        assertTrue(intermediate.certificate().getIssuerX500Principal().getName().contains("Acme Root"));
        assertTrue(intermediate.certificate().getSubjectX500Principal().getName().contains("Acme Intermediate"));

        IssuedCertificate leaf = CertificateIssuer.issue()
                .csr(CsrBuilder.httpsCsr().dns("app.acme.com").build(leafKeys).request())
                .policy(PolicyBuilder.httpsPolicy().build())
                .using(intermediate.certificate(), intKeys.getPrivate())
                .issue();

        leaf.certificate().verify(intermediate.certificate().getPublicKey());
        assertFalse(leaf.certificate().getBasicConstraints() >= 0);
        assertTrue(leaf.certificate().getIssuerX500Principal().getName().contains("Acme Intermediate"));
    }

    @Test
    void selfSignedKeyPair_mustMatchCsr() {
        KeyPair other = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        var csr = CsrBuilder.signingCsr().commonName("Acme Root").build(caKeys);
        assertThrows(IllegalArgumentException.class, () -> CertificateIssuer.issue()
                .csr(csr.request())
                .policy(PolicyBuilder.signingPolicy().build())
                .selfSigned(other));
    }

    private static boolean hasDnsSan(X509Certificate certificate, String dns) throws Exception {
        Collection<List<?>> names = certificate.getSubjectAlternativeNames();
        if (names == null) {
            return false;
        }
        for (List<?> name : names) {
            if (Integer.valueOf(2).equals(name.get(0)) && dns.equals(name.get(1))) {
                return true;
            }
        }
        return false;
    }

    private IssuedCertificate issueCa() {
        var csr = CsrBuilder.signingCsr().commonName("Acme Root").build(caKeys);
        return CertificateIssuer.issue()
                .csr(csr.request())
                .policy(PolicyBuilder.signingPolicy().build())
                .selfSigned(caKeys)
                .issue();
    }
}
