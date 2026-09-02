package com.tbr.pki.tseal.csr;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

class CsrEngineTest {

    // ── key passing ───────────────────────────────────────────────────────────

    @Test
    void build_splitKeys_producesValidCsr() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.RSA_2048);
        var acc = new CsrAccumulator();
        acc.subjectBuilder.addRDN(org.bouncycastle.asn1.x500.style.BCStyle.CN, "split-key");

        CsrResult result = CsrEngine.build(acc, kp.getPublic(), kp.getPrivate(), null);

        assertNotNull(result.request());
        assertFalse(result.pem().isBlank());
    }

    @Test
    void build_explicitContentSigner_usedDirectly() throws Exception {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        ContentSigner explicitSigner = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(kp.getPrivate());

        var acc = new CsrAccumulator();
        acc.subjectBuilder.addRDN(org.bouncycastle.asn1.x500.style.BCStyle.CN, "explicit-signer");
        acc.sanEntries.add(new GeneralName(GeneralName.dNSName, "explicit.example.com"));

        CsrResult result = CsrEngine.build(acc, kp.getPublic(), null, explicitSigner);

        assertEquals(X9ObjectIdentifiers.ecdsa_with_SHA256,
                result.request().getSignatureAlgorithm().getAlgorithm());
    }

    @Test
    void build_contentSignerOverrideInAccumulator_usedOverDerivation() throws Exception {
        KeyPair ecKey = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        ContentSigner override = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(ecKey.getPrivate());

        var acc = new CsrAccumulator();
        acc.subjectBuilder.addRDN(org.bouncycastle.asn1.x500.style.BCStyle.CN, "override");
        acc.contentSignerOverride = override;

        CsrResult result = CsrEngine.build(acc, ecKey.getPublic(), null, null);

        assertNotNull(result.request());
    }

    @Test
    void build_signatureAlgorithmOverride_usesSpecifiedAlgorithm() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.RSA_2048);
        var acc = new CsrAccumulator();
        acc.subjectBuilder.addRDN(org.bouncycastle.asn1.x500.style.BCStyle.CN, "alg-override");
        acc.signatureAlgorithmOverride = "SHA512withRSA";

        CsrResult result = CsrEngine.build(acc, kp.getPublic(), kp.getPrivate(), null);

        ASN1ObjectIdentifier alg = result.request().getSignatureAlgorithm().getAlgorithm();
        assertEquals(PKCSObjectIdentifiers.sha512WithRSAEncryption, alg);
    }

    // ── adaptive key usage ────────────────────────────────────────────────────

    @Test
    void adaptiveKeyUsage_rsaKey_includesKeyEncipherment() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.RSA_2048);
        var acc = new CsrAccumulator();
        acc.adaptiveKeyUsage = true;
        acc.sanEntries.add(new GeneralName(GeneralName.dNSName, "rsa.example.com"));

        Extensions exts = singleExtensionRequest(CsrEngine.build(acc, kp.getPublic(), kp.getPrivate(), null).request());

        KeyUsage ku = KeyUsage.fromExtensions(exts);
        assertTrue(ku.hasUsages(KeyUsage.digitalSignature));
        assertTrue(ku.hasUsages(KeyUsage.keyEncipherment));
    }

    @Test
    void adaptiveKeyUsage_ecKey_excludesKeyEncipherment() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        var acc = new CsrAccumulator();
        acc.adaptiveKeyUsage = true;
        acc.sanEntries.add(new GeneralName(GeneralName.dNSName, "ec.example.com"));

        Extensions exts = singleExtensionRequest(CsrEngine.build(acc, kp.getPublic(), kp.getPrivate(), null).request());

        KeyUsage ku = KeyUsage.fromExtensions(exts);
        assertTrue(ku.hasUsages(KeyUsage.digitalSignature));
        assertFalse(ku.hasUsages(KeyUsage.keyEncipherment));
    }

    // ── SAN handling ──────────────────────────────────────────────────────────

    @Test
    void emptySanEntries_noSanExtension() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        var acc = new CsrAccumulator();
        acc.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));

        Extensions exts = singleExtensionRequest(CsrEngine.build(acc, kp.getPublic(), kp.getPrivate(), null).request());

        assertNull(GeneralNames.fromExtensions(exts, Extension.subjectAlternativeName));
    }

    @Test
    void nonEmptySanEntries_sanExtensionPresent() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        var acc = new CsrAccumulator();
        acc.sanEntries.add(new GeneralName(GeneralName.dNSName, "san.example.com"));
        acc.sanEntries.add(new GeneralName(GeneralName.iPAddress, "10.0.0.1"));

        Extensions exts = singleExtensionRequest(CsrEngine.build(acc, kp.getPublic(), kp.getPrivate(), null).request());

        GeneralNames san = GeneralNames.fromExtensions(exts, Extension.subjectAlternativeName);
        assertNotNull(san);
        assertEquals(2, san.getNames().length);
    }

    // ── no extensions → no extensionRequest attribute ─────────────────────────

    @Test
    void noExtensions_noExtensionRequestAttribute() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        var acc = new CsrAccumulator();
        acc.subjectBuilder.addRDN(org.bouncycastle.asn1.x500.style.BCStyle.CN, "no-exts");

        PKCS10CertificationRequest csr = CsrEngine.build(acc, kp.getPublic(), kp.getPrivate(), null).request();

        Attribute[] attrs = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        assertEquals(0, attrs.length);
    }

    // ── algorithm derivation ──────────────────────────────────────────────────

    @Test
    void algorithmDerivation_ecP384_sha384() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P384);
        CsrResult result = CsrEngine.build(minimal(kp), kp.getPublic(), kp.getPrivate(), null);

        assertEquals(X9ObjectIdentifiers.ecdsa_with_SHA384,
                result.request().getSignatureAlgorithm().getAlgorithm());
    }

    @Test
    void algorithmDerivation_ecP521_sha512() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P521);
        CsrResult result = CsrEngine.build(minimal(kp), kp.getPublic(), kp.getPrivate(), null);

        assertEquals(X9ObjectIdentifiers.ecdsa_with_SHA512,
                result.request().getSignatureAlgorithm().getAlgorithm());
    }

    @Test
    void algorithmDerivation_ed25519() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.ED25519);
        CsrResult result = CsrEngine.build(minimal(kp), kp.getPublic(), kp.getPrivate(), null);

        assertEquals(EdECObjectIdentifiers.id_Ed25519,
                result.request().getSignatureAlgorithm().getAlgorithm());
    }

    @Test
    void algorithmDerivation_ed448() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.ED448);
        CsrResult result = CsrEngine.build(minimal(kp), kp.getPublic(), kp.getPrivate(), null);

        assertEquals(EdECObjectIdentifiers.id_Ed448,
                result.request().getSignatureAlgorithm().getAlgorithm());
    }

    // ── requested validity ────────────────────────────────────────────────────

    @Test
    void requestedValidity_writtenAsNonCriticalIntegerSeconds() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        var acc = new CsrAccumulator();
        acc.subjectBuilder.addRDN(org.bouncycastle.asn1.x500.style.BCStyle.CN, "ttl");
        acc.requestedValidity(Duration.ofDays(30));

        Extensions exts = singleExtensionRequest(CsrEngine.build(acc, kp.getPublic(), kp.getPrivate(), null).request());

        Extension ext = exts.getExtension(Oids.REQUESTED_VALIDITY);
        assertNotNull(ext);
        assertFalse(ext.isCritical());
        assertEquals(Duration.ofDays(30).toSeconds(),
                ASN1Integer.getInstance(exts.getExtensionParsedValue(Oids.REQUESTED_VALIDITY))
                        .getValue().longValueExact());
    }

    @Test
    void requestedValidity_absent_omittedFromExtensions() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        var acc = new CsrAccumulator();
        acc.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));

        Extensions exts = singleExtensionRequest(CsrEngine.build(acc, kp.getPublic(), kp.getPrivate(), null).request());

        assertNull(exts.getExtension(Oids.REQUESTED_VALIDITY));
    }

    // ── extra attributes ──────────────────────────────────────────────────────

    @Test
    void extraAttributes_includedInCsr() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        var customOid = new ASN1ObjectIdentifier("1.2.3.4.5");
        var acc = new CsrAccumulator();
        acc.extraAttributes.add(new CsrAccumulator.CsrAttribute(customOid, new DERPrintableString("test-value")));

        PKCS10CertificationRequest csr = CsrEngine.build(acc, kp.getPublic(), kp.getPrivate(), null).request();

        Attribute[] attrs = csr.getAttributes(customOid);
        assertEquals(1, attrs.length);
        assertEquals("test-value", DERPrintableString.getInstance(attrs[0].getAttrValues().getObjectAt(0)).getString());
    }

    // ── RawCsr.subjectRdn ─────────────────────────────────────────────────────

    @Test
    void subjectRdn_viaRawCsr_appearsInSubject() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        var acc = new CsrAccumulator();
        new RawCsrImpl(acc).subjectRdn(org.bouncycastle.asn1.x500.style.BCStyle.O, new DERPrintableString("RawOrg"));

        X500Name subject = CsrEngine.build(acc, kp.getPublic(), kp.getPrivate(), null)
                .request().getSubject();

        assertTrue(subject.toString().contains("RawOrg"));
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private static CsrAccumulator minimal(KeyPair kp) {
        var acc = new CsrAccumulator();
        acc.subjectBuilder.addRDN(org.bouncycastle.asn1.x500.style.BCStyle.CN, "test");
        return acc;
    }

    private static Extensions singleExtensionRequest(PKCS10CertificationRequest csr) {
        Attribute[] attrs = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        assertEquals(1, attrs.length, "expected exactly one extensionRequest attribute");
        return Extensions.getInstance(ASN1Sequence.getInstance(attrs[0].getAttrValues().getObjectAt(0)));
    }
}
