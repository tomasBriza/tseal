package io.github.tomasbriza.tseal.issue;

import io.github.tomasbriza.tseal.policy.CallerValues;
import io.github.tomasbriza.tseal.policy.IssuancePolicy;
import io.github.tomasbriza.tseal.policy.PolicyViolation;
import io.github.tomasbriza.tseal.policy.ViolationCodes;
import io.github.tomasbriza.tseal.policy.engine.CsrView;

import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
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
    private String backdateError;
    private BigInteger serial;
    private String serialError;
    private String keyError;
    private BiConsumer<CallerValues, RawIssuedCertificate> customizer;

    @Override
    public CertificateIssueBuilder csr(PKCS10CertificationRequest csr) {
        this.csr = csr;
        return this;
    }

    @Override
    public CertificateIssueBuilder csr(String pem) {
        this.csr = CsrView.parsePem(pem);
        return this;
    }

    @Override
    public CertificateIssueBuilder policy(IssuancePolicy policy) {
        this.policy = policy;
        return this;
    }

    @Override
    public CertificateIssueBuilder using(X509Certificate issuerCertificate, PrivateKey issuerKey) {
        this.issuerCertificate = issuerCertificate;
        this.issuerKey = issuerKey;
        this.explicitSigner = null;
        this.selfSigned = false;
        this.keyError = null;
        return this;
    }

    @Override
    public CertificateIssueBuilder using(X509Certificate issuerCertificate, KeyPair issuerKeyPair) {
        using(issuerCertificate, issuerKeyPair == null ? null : issuerKeyPair.getPrivate());
        if (issuerCertificate != null && issuerKeyPair != null
                && !Arrays.equals(issuerCertificate.getPublicKey().getEncoded(),
                        issuerKeyPair.getPublic().getEncoded())) {
            this.keyError = "issuer KeyPair public key does not match the issuer certificate";
        }
        return this;
    }

    @Override
    public CertificateIssueBuilder using(X509Certificate issuerCertificate, ContentSigner signer) {
        this.issuerCertificate = issuerCertificate;
        this.explicitSigner = signer;
        this.issuerKey = null;
        this.selfSigned = false;
        this.keyError = null;
        return this;
    }

    @Override
    public CertificateIssueBuilder selfSigned(PrivateKey subjectKey) {
        this.selfSigned = true;
        this.issuerKey = subjectKey;
        this.issuerCertificate = null;
        this.explicitSigner = null;
        this.keyError = null;
        return this;
    }

    @Override
    public CertificateIssueBuilder selfSigned(KeyPair subjectKeyPair) {
        selfSigned(subjectKeyPair == null ? null : subjectKeyPair.getPrivate());
        if (subjectKeyPair == null || csr == null) {
            return this;
        }
        byte[] csrKey = csrPublicKeyEncoded();
        if (csrKey == null || !Arrays.equals(csrKey, subjectKeyPair.getPublic().getEncoded())) {
            this.keyError = "self-signed public key does not match the CSR";
        }
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
            this.serial = null;
            this.serialError = "serial must be a positive integer";
        } else {
            this.serial = serial;
            this.serialError = null;
        }
        return this;
    }

    @Override
    public CertificateIssueBuilder backdate(Duration skew) {
        if (skew == null || skew.isNegative()) {
            this.backdateError = "backdate must be zero or positive";
        } else {
            this.backdate = skew;
            this.backdateError = null;
        }
        return this;
    }

    @Override
    public CertificateIssueBuilder customize(BiConsumer<CallerValues, RawIssuedCertificate> customizer) {
        this.customizer = Objects.requireNonNull(customizer, "customizer");
        return this;
    }

    @Override
    public IssueResult issue() {
        List<PolicyViolation> problems = new ArrayList<>();
        if (csr == null) {
            problems.add(violation("csr", "csr is required", ViolationCodes.ISSUE_INPUT));
        }
        if (policy == null) {
            problems.add(violation("policy", "policy is required", ViolationCodes.ISSUE_INPUT));
        }
        if (explicitSigner == null && issuerKey == null) {
            problems.add(violation("signer", "issuer key or ContentSigner is required", ViolationCodes.ISSUE_INPUT));
        }
        if (!selfSigned && issuerCertificate == null) {
            problems.add(violation("issuer", "issuer certificate is required", ViolationCodes.ISSUE_INPUT));
        }
        if (serialError != null) {
            problems.add(violation("serial", serialError, ViolationCodes.ISSUE_INPUT));
        }
        if (backdateError != null) {
            problems.add(violation("backdate", backdateError, ViolationCodes.ISSUE_INPUT));
        }
        if (keyError != null) {
            problems.add(violation("publicKey", keyError, ViolationCodes.KEY_MISMATCH));
        }
        if (!problems.isEmpty()) {
            return new IssueResult.Rejected(problems);
        }
        return IssueEngine.issue(
                csr, policy, caller, issuerCertificate, issuerKey, explicitSigner,
                selfSigned, clock, backdate, serial, customizer);
    }

    private static PolicyViolation violation(String field, String message, String code) {
        return new PolicyViolation(field, message, code);
    }

    private byte[] csrPublicKeyEncoded() {
        try {
            return new JcaPKCS10CertificationRequest(csr).getPublicKey().getEncoded();
        } catch (Exception e) {
            return null;
        }
    }
}
