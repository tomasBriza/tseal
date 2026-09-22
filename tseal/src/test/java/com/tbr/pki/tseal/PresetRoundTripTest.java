package com.tbr.pki.tseal;

import com.tbr.pki.tseal.csr.CsrBuilder;
import com.tbr.pki.tseal.csr.CsrResult;
import com.tbr.pki.tseal.issue.CertificateIssuer;
import com.tbr.pki.tseal.issue.IssuedCertificate;
import com.tbr.pki.tseal.key.KeyAlgorithm;
import com.tbr.pki.tseal.key.KeyPairFactory;
import com.tbr.pki.tseal.policy.IssuancePolicy;
import com.tbr.pki.tseal.policy.PolicyBuilder;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PresetRoundTripTest {

    private KeyPair caKeys;
    private IssuedCertificate ca;

    @BeforeEach
    void issueRoot() {
        caKeys = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        var csr = CsrBuilder.signingCsr().commonName("Round-trip Root").build(caKeys);
        ca = CertificateIssuer.issue()
                .csr(csr.request())
                .policy(PolicyBuilder.signingPolicy().unboundedPathLen().build())
                .selfSigned(caKeys)
                .issue();
    }

    @Test
    void httpsCsr_passesHttpsPolicy_andIssues() throws Exception {
        KeyPair leafKeys = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        CsrResult csr = CsrBuilder.httpsCsr()
                .commonName("app")
                .dns("app.example.com")
                .build(leafKeys);
        IssuancePolicy policy = PolicyBuilder.httpsPolicy().build();

        policy.check(csr.request());
        IssuedCertificate leaf = CertificateIssuer.issue()
                .csr(csr.request())
                .policy(policy)
                .using(ca.certificate(), caKeys.getPrivate())
                .issue();

        leaf.certificate().verify(ca.certificate().getPublicKey());
        assertFalse(leaf.certificate().getBasicConstraints() >= 0);
    }

    @Test
    void clientAuthCsr_passesClientAuthPolicy_andIssues() throws Exception {
        KeyPair leafKeys = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        CsrResult csr = CsrBuilder.clientAuthCsr()
                .commonName("client-app")
                .build(leafKeys);
        IssuancePolicy policy = PolicyBuilder.clientAuthPolicy().build();

        policy.check(csr.request());
        IssuedCertificate leaf = CertificateIssuer.issue()
                .csr(csr.request())
                .policy(policy)
                .using(ca.certificate(), caKeys.getPrivate())
                .issue();

        leaf.certificate().verify(ca.certificate().getPublicKey());
        assertFalse(leaf.certificate().getBasicConstraints() >= 0);
    }

    @Test
    void signingCsr_passesSigningPolicy_andIssuesIntermediate() throws Exception {
        KeyPair intKeys = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        CsrResult csr = CsrBuilder.signingCsr()
                .commonName("Round-trip Intermediate")
                .build(intKeys);
        IssuancePolicy policy = PolicyBuilder.signingPolicy().pathLen(0).build();

        policy.check(csr.request());
        IssuedCertificate intermediate = CertificateIssuer.issue()
                .csr(csr.request())
                .policy(policy)
                .using(ca.certificate(), caKeys.getPrivate())
                .issue();

        intermediate.certificate().verify(ca.certificate().getPublicKey());
        assertTrue(intermediate.certificate().getBasicConstraints() >= 0);
    }
}
