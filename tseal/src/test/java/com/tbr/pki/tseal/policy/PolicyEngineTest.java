package com.tbr.pki.tseal.policy;

import com.tbr.pki.tseal.csr.CsrBuilder;
import com.tbr.pki.tseal.csr.CsrResult;
import com.tbr.pki.tseal.csr.KeyAlgorithm;
import com.tbr.pki.tseal.csr.KeyPairFactory;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PolicyEngineTest {

    @Test
    void https_adaptiveKeyUsage_ec_digitalSignatureOnly() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        CsrResult csr = CsrBuilder.httpsCsr().dns("app.example.com").build(kp);
        Evaluation ev = evaluateHttps(csr);

        assertTrue(ev.ok(), ev.violations::toString);
        assertNotNull(ev.keyUsageBits);
        assertTrue((ev.keyUsageBits & KeyUsage.digitalSignature) != 0);
        assertEquals(0, ev.keyUsageBits & KeyUsage.keyEncipherment);
        BasicConstraints bc = BasicConstraints.fromExtensions(ev.extensions);
        assertFalse(bc.isCA());
    }

    @Test
    void https_adaptiveKeyUsage_rsa_includesKeyEncipherment() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.RSA_2048);
        CsrResult csr = CsrBuilder.httpsCsr().dns("app.example.com").build(kp);
        Evaluation ev = evaluateHttps(csr);

        assertTrue(ev.ok(), ev.violations::toString);
        assertTrue((ev.keyUsageBits & KeyUsage.keyEncipherment) != 0);
    }

    @Test
    void https_crlAndOcsp_materialized() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        CsrResult csr = CsrBuilder.httpsCsr().dns("app.example.com").build(kp);
        var acc = new HttpsPolicyBuilder()
                .crl("http://crl.acme.com/acme.crl")
                .crl("http://crl-backup.acme.com/acme.crl")
                .ocsp("http://ocsp.acme.com")
                .caIssuers("http://ca.acme.com/acme.crt")
                .build();
        Evaluation ev = PolicyEngine.evaluate(acc.spec, csr.request(), CallerValues.empty());

        assertTrue(ev.ok(), ev.violations::toString);
        CRLDistPoint crl = CRLDistPoint.fromExtensions(ev.extensions);
        assertEquals(2, crl.getDistributionPoints().length);
        AuthorityInformationAccess aia = AuthorityInformationAccess.fromExtensions(ev.extensions);
        assertEquals(2, aia.getAccessDescriptions().length);
        assertEquals(AccessDescription.id_ad_ocsp, aia.getAccessDescriptions()[0].getAccessMethod());
        assertEquals(AccessDescription.id_ad_caIssuers, aia.getAccessDescriptions()[1].getAccessMethod());
        assertFalse(ev.extensions.getExtension(Extension.cRLDistributionPoints).isCritical());
        assertFalse(ev.extensions.getExtension(Extension.authorityInfoAccess).isCritical());
    }

    @Test
    void validity_fromCsr_resolved() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        CsrResult csr = CsrBuilder.httpsCsr()
                .dns("app.example.com")
                .validity(Duration.ofDays(30))
                .build(kp);
        Evaluation ev = evaluateHttps(csr);
        assertTrue(ev.ok(), ev.violations::toString);
        assertEquals(Duration.ofDays(30), ev.validity);
    }

    @Test
    void validity_default_whenOmitted() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        CsrResult csr = CsrBuilder.httpsCsr().dns("app.example.com").build(kp);
        Evaluation ev = evaluateHttps(csr);
        assertTrue(ev.ok(), ev.violations::toString);
        assertEquals(Duration.ofDays(90), ev.validity);
    }

    @Test
    void signing_pathLenZero() {
        KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.RSA_2048);
        CsrResult csr = CsrBuilder.signingCsr().commonName("CA").build(kp);
        Evaluation ev = PolicyEngine.evaluate(
                PolicyBuilder.signingPolicy().build().spec, csr.request(), CallerValues.empty());
        assertTrue(ev.ok(), ev.violations::toString);
        BasicConstraints bc = BasicConstraints.fromExtensions(ev.extensions);
        assertTrue(bc.isCA());
        assertEquals(0, bc.getPathLenConstraint().intValue());
    }

    private static Evaluation evaluateHttps(CsrResult csr) {
        return PolicyEngine.evaluate(PolicyBuilder.httpsPolicy().build().spec, csr.request(), CallerValues.empty());
    }
}
