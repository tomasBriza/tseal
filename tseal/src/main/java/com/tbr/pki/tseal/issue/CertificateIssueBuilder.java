package com.tbr.pki.tseal.issue;

import com.tbr.pki.tseal.policy.CallerValues;
import com.tbr.pki.tseal.policy.IssuancePolicy;
import com.tbr.pki.tseal.policy.engine.CsrView;

import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.BiConsumer;

public final class CertificateIssueBuilder implements IssueStart, IssueWithCsr, IssueWithPolicy, IssueBuildable {

    private PKCS10CertificationRequest csr;
    private IssuancePolicy policy;
    private CallerValues caller = CallerValues.empty();
    private X509Certificate issuerCertificate;
    private PrivateKey issuerKey;
    private ContentSigner explicitSigner;
    private boolean selfSigned;
    private Clock clock = Clock.systemUTC();
    private Duration backdate = Duration.ofMinutes(5);
    private BigInteger serial;
    private BiConsumer<CallerValues, RawIssuedCertificate> customizer;

    @Override
    public CertificateIssueBuilder csr(PKCS10CertificationRequest csr) {
        this.csr = Objects.requireNonNull(csr, "csr");
        return this;
    }

    @Override
    public CertificateIssueBuilder csr(String pem) {
        this.csr = CsrView.parsePem(pem);
        return this;
    }

    @Override
    public CertificateIssueBuilder policy(IssuancePolicy policy) {
        this.policy = Objects.requireNonNull(policy, "policy");
        return this;
    }

    @Override
    public CertificateIssueBuilder using(X509Certificate issuerCertificate, PrivateKey issuerKey) {
        this.issuerCertificate = Objects.requireNonNull(issuerCertificate, "issuerCertificate");
        this.issuerKey = Objects.requireNonNull(issuerKey, "issuerKey");
        this.explicitSigner = null;
        this.selfSigned = false;
        return this;
    }

    @Override
    public CertificateIssueBuilder using(X509Certificate issuerCertificate, KeyPair issuerKeyPair) {
        Objects.requireNonNull(issuerKeyPair, "issuerKeyPair");
        requireSameKey(issuerCertificate.getPublicKey().getEncoded(), issuerKeyPair.getPublic().getEncoded(),
                "issuer KeyPair public key does not match the issuer certificate");
        return using(issuerCertificate, issuerKeyPair.getPrivate());
    }

    @Override
    public CertificateIssueBuilder using(X509Certificate issuerCertificate, ContentSigner signer) {
        this.issuerCertificate = Objects.requireNonNull(issuerCertificate, "issuerCertificate");
        this.explicitSigner = Objects.requireNonNull(signer, "signer");
        this.issuerKey = null;
        this.selfSigned = false;
        return this;
    }

    @Override
    public CertificateIssueBuilder selfSigned(PrivateKey subjectKey) {
        this.selfSigned = true;
        this.issuerKey = Objects.requireNonNull(subjectKey, "subjectKey");
        this.issuerCertificate = null;
        this.explicitSigner = null;
        return this;
    }

    @Override
    public CertificateIssueBuilder selfSigned(KeyPair subjectKeyPair) {
        Objects.requireNonNull(subjectKeyPair, "subjectKeyPair");
        requireSameKey(csrPublicKeyEncoded(), subjectKeyPair.getPublic().getEncoded(),
                "self-signed KeyPair public key does not match the CSR");
        this.selfSigned = true;
        this.issuerKey = subjectKeyPair.getPrivate();
        this.issuerCertificate = null;
        this.explicitSigner = null;
        return this;
    }

    @Override
    public CertificateIssueBuilder caller(CallerValues caller) {
        this.caller = caller == null ? CallerValues.empty() : caller;
        return this;
    }

    @Override
    public CertificateIssueBuilder clock(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
        return this;
    }

    @Override
    public CertificateIssueBuilder serial(BigInteger serial) {
        if (serial == null || serial.signum() <= 0) {
            throw new IllegalArgumentException("serial must be a positive integer");
        }
        this.serial = serial;
        return this;
    }

    @Override
    public CertificateIssueBuilder backdate(Duration skew) {
        if (skew == null || skew.isNegative()) {
            throw new IllegalArgumentException("backdate must be zero or positive");
        }
        this.backdate = skew;
        return this;
    }

    @Override
    public CertificateIssueBuilder customize(BiConsumer<CallerValues, RawIssuedCertificate> customizer) {
        this.customizer = Objects.requireNonNull(customizer, "customizer");
        return this;
    }

    @Override
    public IssuedCertificate issue() {
        return IssueEngine.issue(
                csr, policy, caller, issuerCertificate, issuerKey, explicitSigner,
                selfSigned, clock, backdate, serial, customizer);
    }

    private byte[] csrPublicKeyEncoded() {
        try {
            return new JcaPKCS10CertificationRequest(csr).getPublicKey().getEncoded();
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to read CSR public key", e);
        }
    }

    private static void requireSameKey(byte[] expected, byte[] actual, String message) {
        if (!Arrays.equals(expected, actual)) {
            throw new IllegalArgumentException(message);
        }
    }
}
