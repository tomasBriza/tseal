package com.tbr.pki.tseal.csr;

import com.tbr.pki.tseal.key.KeyAlgorithm;
import com.tbr.pki.tseal.key.KeyPairFactory;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.security.KeyPair;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

class CsrBuilderTest {

    // ── httpsCsr ──────────────────────────────────────────────────────────────

    @Test
    void httpsCsr_dns_rsa_producesCorrectExtensions() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.RSA_2048);
        CsrResult result = CsrBuilder.httpsCsr()
                .commonName("server.example.com")
                .dns("server.example.com")
                .build(kp);

        assertPemPresent(result);
        Extensions exts = singleExtensionRequest(result.request());

        KeyUsage ku = KeyUsage.fromExtensions(exts);
        assertTrue(ku.hasUsages(KeyUsage.digitalSignature), "digitalSignature");
        assertTrue(ku.hasUsages(KeyUsage.keyEncipherment), "keyEncipherment (RSA)");

        ExtendedKeyUsage eku = ExtendedKeyUsage.fromExtensions(exts);
        assertTrue(eku.hasKeyPurposeId(KeyPurposeId.id_kp_serverAuth), "serverAuth");

        BasicConstraints bc = BasicConstraints.fromExtensions(exts);
        assertFalse(bc.isCA(), "CA=false");
    }

    @Test
    void httpsCsr_dns_ec_omitsKeyEncipherment() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        CsrResult result = CsrBuilder.httpsCsr()
                .commonName("server.example.com")
                .dns("server.example.com")
                .build(kp);

        KeyUsage ku = KeyUsage.fromExtensions(singleExtensionRequest(result.request()));
        assertTrue(ku.hasUsages(KeyUsage.digitalSignature), "digitalSignature");
        assertFalse(ku.hasUsages(KeyUsage.keyEncipherment), "no keyEncipherment for EC");
    }

    @Test
    void httpsCsr_ip_unlocksBuild() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        CsrResult result = CsrBuilder.httpsCsr()
                .commonName("internal")
                .ip("10.0.0.1")
                .build(kp);

        assertPemPresent(result);
        Extensions exts = singleExtensionRequest(result.request());
        GeneralNames san = GeneralNames.fromExtensions(exts, Extension.subjectAlternativeName);
        assertNotNull(san);
        assertEquals(GeneralName.iPAddress, san.getNames()[0].getTagNo());
    }

    @Test
    void httpsCsr_multipleSan() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.RSA_2048);
        CsrResult result = CsrBuilder.httpsCsr()
                .commonName("server")
                .dns("server.example.com")
                .dns("www.example.com")
                .ip("192.168.1.1")
                .build(kp);

        GeneralNames san = GeneralNames.fromExtensions(
                singleExtensionRequest(result.request()), Extension.subjectAlternativeName);
        assertEquals(3, san.getNames().length);
    }

    @Test
    void httpsCsr_validity_writesRequestedLifetimeSeconds() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        CsrResult result = CsrBuilder.httpsCsr()
                .commonName("server")
                .validity(Duration.ofDays(30))
                .dns("server.example.com")
                .build(kp);

        Extensions exts = singleExtensionRequest(result.request());
        assertEquals(Duration.ofDays(30).toSeconds(), requestedValiditySeconds(exts));
        assertFalse(exts.getExtension(Oids.REQUESTED_VALIDITY).isCritical());
    }

    @Test
    void httpsCsr_validity_doesNotReplaceSanRequirement() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        CsrResult result = CsrBuilder.httpsCsr()
                .dns("server.example.com")
                .validity(Duration.ofDays(7))
                .build(kp);

        assertEquals(Duration.ofDays(7).toSeconds(),
                requestedValiditySeconds(singleExtensionRequest(result.request())));
    }

    @Test
    void validity_rejectsNullZeroAndNegative() {
        assertThrows(IllegalArgumentException.class,
                () -> CsrBuilder.clientAuthCsr().validity(null));
        assertThrows(IllegalArgumentException.class,
                () -> CsrBuilder.clientAuthCsr().validity(Duration.ZERO));
        assertThrows(IllegalArgumentException.class,
                () -> CsrBuilder.clientAuthCsr().validity(Duration.ofDays(-1)));
        assertThrows(IllegalArgumentException.class,
                () -> CsrBuilder.clientAuthCsr().validity(Duration.ofMillis(500)));
    }

    @Test
    void validity_lastCallWins() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        CsrResult result = CsrBuilder.clientAuthCsr()
                .commonName("client")
                .validity(Duration.ofDays(90))
                .validity(Duration.ofDays(14))
                .build(kp);

        assertEquals(Duration.ofDays(14).toSeconds(),
                requestedValiditySeconds(singleExtensionRequest(result.request())));
    }

    @Test
    void clientAuthCsr_validity_present() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        Extensions exts = singleExtensionRequest(CsrBuilder.clientAuthCsr()
                .commonName("client-app")
                .validity(Duration.ofDays(365))
                .build(kp)
                .request());

        assertEquals(Duration.ofDays(365).toSeconds(), requestedValiditySeconds(exts));
    }

    @Test
    void signingCsr_validity_present() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.RSA_2048);
        Extensions exts = singleExtensionRequest(CsrBuilder.signingCsr()
                .commonName("Intermediate CA")
                .validity(Duration.ofDays(1825))
                .build(kp)
                .request());

        assertEquals(Duration.ofDays(1825).toSeconds(), requestedValiditySeconds(exts));
    }

    @Test
    void custom_validity_present() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        Extensions exts = singleExtensionRequest(CsrBuilder.custom()
                .subject().commonName("custom").and()
                .validity(Duration.ofHours(12))
                .build(kp)
                .request());

        assertEquals(Duration.ofHours(12).toSeconds(), requestedValiditySeconds(exts));
    }

    @Test
    void httpsCsr_withoutValidity_omitsRequestedValidityExtension() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        Extensions exts = singleExtensionRequest(CsrBuilder.httpsCsr()
                .dns("server.example.com")
                .build(kp)
                .request());

        assertNull(exts.getExtension(Oids.REQUESTED_VALIDITY));
    }

    // ── clientAuthCsr ─────────────────────────────────────────────────────────

    @Test
    void clientAuthCsr_correctExtensions() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        CsrResult result = CsrBuilder.clientAuthCsr()
                .commonName("client-app")
                .build(kp);

        assertPemPresent(result);
        Extensions exts = singleExtensionRequest(result.request());

        KeyUsage ku = KeyUsage.fromExtensions(exts);
        assertTrue(ku.hasUsages(KeyUsage.digitalSignature));
        assertFalse(ku.hasUsages(KeyUsage.keyEncipherment));

        ExtendedKeyUsage eku = ExtendedKeyUsage.fromExtensions(exts);
        assertTrue(eku.hasKeyPurposeId(KeyPurposeId.id_kp_clientAuth));

        BasicConstraints bc = BasicConstraints.fromExtensions(exts);
        assertFalse(bc.isCA());
    }

    // ── signingCsr ────────────────────────────────────────────────────────────

    @Test
    void signingCsr_correctExtensions() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.RSA_4096);
        CsrResult result = CsrBuilder.signingCsr()
                .commonName("Intermediate CA")
                .organization("Acme Corp")
                .build(kp);

        assertPemPresent(result);
        Extensions exts = singleExtensionRequest(result.request());

        KeyUsage ku = KeyUsage.fromExtensions(exts);
        assertTrue(ku.hasUsages(KeyUsage.keyCertSign));
        assertTrue(ku.hasUsages(KeyUsage.cRLSign));

        BasicConstraints bc = BasicConstraints.fromExtensions(exts);
        assertTrue(bc.isCA());
    }

    // ── custom() ──────────────────────────────────────────────────────────────

    @Test
    void custom_subjectAndSan() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P384);
        CsrResult result = CsrBuilder.custom()
                .subject()
                    .commonName("test")
                    .organization("Acme")
                    .country("CZ")
                .and()
                .san()
                    .dns("test.example.com")
                    .email("svc@example.com")
                .and()
                .keyUsage(KeyUsage.digitalSignature)
                .build(kp);

        assertPemPresent(result);
        Extensions exts = singleExtensionRequest(result.request());
        GeneralNames san = GeneralNames.fromExtensions(exts, Extension.subjectAlternativeName);
        assertEquals(2, san.getNames().length);
    }

    @Test
    void custom_rawEscapeHatch() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        CsrResult result = CsrBuilder.custom()
                .subject().commonName("escape").and()
                .san().dns("escape.example.com").and()
                .custom(raw -> raw.signatureAlgorithm("SHA256withECDSA"))
                .build(kp);

        assertPemPresent(result);
    }

    // ── key pair generation ───────────────────────────────────────────────────

    @ParameterizedTest
    @EnumSource(KeyAlgorithm.class)
    void keyPairFactory_allAlgorithms(KeyAlgorithm algorithm) {
        KeyPair kp = assertDoesNotThrow(() -> KeyPairFactory.generate(algorithm));
        assertNotNull(kp.getPublic());
        assertNotNull(kp.getPrivate());
    }

    // ── signature verification ────────────────────────────────────────────────

    @Test
    void httpsCsr_signatureVerifies() throws Exception {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        CsrResult result = CsrBuilder.httpsCsr()
                .commonName("server")
                .dns("server.example.com")
                .build(kp);

        assertTrue(result.request().isSignatureValid(
                new org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder()
                        .setProvider(org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME)
                        .build(kp.getPublic())));
    }

    // ── single extensionRequest invariant ────────────────────────────────────

    @Test
    void singleExtensionRequestAttribute() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.RSA_2048);
        CsrResult result = CsrBuilder.httpsCsr()
                .commonName("server")
                .dns("server.example.com")
                .build(kp);

        Attribute[] attrs = result.request().getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        assertEquals(1, attrs.length, "exactly one extensionRequest attribute");
    }

    // ── pem ───────────────────────────────────────────────────────────────────

    @Test
    void pemContainsCsrHeader() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        String pem = CsrBuilder.httpsCsr()
                .dns("x.example.com")
                .build(kp)
                .pem();

        assertTrue(pem.contains("-----BEGIN CERTIFICATE REQUEST-----"));
        assertTrue(pem.contains("-----END CERTIFICATE REQUEST-----"));
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private static void assertPemPresent(CsrResult result) {
        assertNotNull(result.request());
        assertNotNull(result.pem());
        assertFalse(result.pem().isBlank());
    }

    /**
     * Asserts there is exactly one extensionRequest attribute and returns its Extensions.
     */
    private static Extensions singleExtensionRequest(PKCS10CertificationRequest csr) {
        Attribute[] attrs = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        assertEquals(1, attrs.length, "expected exactly one extensionRequest attribute");
        ASN1Sequence seq = ASN1Sequence.getInstance(attrs[0].getAttrValues().getObjectAt(0));
        return Extensions.getInstance(seq);
    }

    private static long requestedValiditySeconds(Extensions exts) {
        ASN1Integer value = ASN1Integer.getInstance(exts.getExtensionParsedValue(Oids.REQUESTED_VALIDITY));
        assertNotNull(value, "expected requested-validity extension");
        return value.getValue().longValueExact();
    }
}
