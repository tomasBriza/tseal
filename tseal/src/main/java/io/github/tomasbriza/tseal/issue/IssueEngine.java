package io.github.tomasbriza.tseal.issue;

import io.github.tomasbriza.tseal.policy.CallerValues;
import io.github.tomasbriza.tseal.policy.Evaluation;
import io.github.tomasbriza.tseal.policy.IssuancePolicy;
import io.github.tomasbriza.tseal.policy.PolicyViolation;
import io.github.tomasbriza.tseal.policy.ViolationCodes;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.function.BiConsumer;

public final class IssueEngine {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private IssueEngine() {
    }

    public static IssueResult issue(
            PKCS10CertificationRequest csr,
            IssuancePolicy policy,
            CallerValues caller,
            X509Certificate issuerCertificate,
            PrivateKey issuerKey,
            ContentSigner explicitSigner,
            boolean selfSigned,
            Clock clock,
            Duration backdate,
            BigInteger serial,
            BiConsumer<CallerValues, RawIssuedCertificate> customizer) {
        if (csr == null) {
            return rejected("csr", "csr is required", ViolationCodes.ISSUE_INPUT);
        }
        if (policy == null) {
            return rejected("policy", "policy is required", ViolationCodes.ISSUE_INPUT);
        }
        if (explicitSigner == null && issuerKey == null) {
            return rejected("signer", "issuer key or ContentSigner is required", ViolationCodes.ISSUE_INPUT);
        }
        if (!selfSigned && issuerCertificate == null) {
            return rejected("issuer", "issuer certificate is required", ViolationCodes.ISSUE_INPUT);
        }
        if (backdate == null || backdate.isNegative()) {
            return rejected("backdate", "backdate must be zero or positive", ViolationCodes.ISSUE_INPUT);
        }
        if (serial != null && serial.signum() <= 0) {
            return rejected("serial", "serial must be a positive integer", ViolationCodes.ISSUE_INPUT);
        }
        IssueResult.Rejected signature = verifyCsrSignature(csr);
        if (signature != null) {
            return signature;
        }
        CallerValues values = caller == null ? CallerValues.empty() : caller;
        switch (policy.check(csr, values)) {
            case Evaluation.Violations rejected -> {
                return new IssueResult.Rejected(rejected.violations());
            }
            case Evaluation.Ok evaluation -> {
                if (!selfSigned && issuerCertificate.getBasicConstraints() < 0) {
                    return rejected("issuer.basicConstraints", "issuer certificate is not a CA",
                            ViolationCodes.ISSUER_NOT_CA);
                }

                PublicKey subjectPublicKey = subjectPublicKey(csr);
                if (subjectPublicKey == null) {
                    return rejected("csr.publicKey", "Failed to read CSR public key", ViolationCodes.ISSUE_FAILED);
                }
                Instant notBefore = clock.instant().minus(backdate);
                Instant notAfter = notBefore.plus(evaluation.validity());
                BigInteger serialNumber = serial != null ? serial : randomSerial();
                X500Name issuerName = selfSigned
                        ? evaluation.subject()
                        : issuerName(issuerCertificate);
                if (issuerName == null) {
                    return rejected("issuer.subject", "Failed to read issuer certificate", ViolationCodes.ISSUE_FAILED);
                }

                try {
                    X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                            issuerName,
                            serialNumber,
                            Date.from(notBefore),
                            Date.from(notAfter),
                            evaluation.subject(),
                            subjectPublicKey);

                    copyPolicyExtensions(builder, evaluation.extensions());
                    if (customizer != null) {
                        customizer.accept(values, new RawIssuedCertificateImpl(builder));
                    }
                    addKeyIdentifiers(builder, subjectPublicKey, issuerCertificate, selfSigned);

                    ContentSigner signer = explicitSigner != null
                            ? explicitSigner
                            : contentSigner(selfSigned ? subjectPublicKey : issuerCertificate.getPublicKey(), issuerKey);
                    X509CertificateHolder holder = builder.build(signer);
                    X509Certificate certificate = new JcaX509CertificateConverter()
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                            .getCertificate(holder);
                    return new IssueResult.Issued(certificate, toPem(certificate));
                } catch (OperatorCreationException | CertificateException | IOException e) {
                    String detail = e.getMessage();
                    String message = detail == null || detail.isBlank()
                            ? "Certificate issuance failed"
                            : "Certificate issuance failed: " + detail;
                    return rejected("issue", message, ViolationCodes.ISSUE_FAILED);
                }
            }
        }
    }

    private static IssueResult.Rejected rejected(String field, String message, String code) {
        return new IssueResult.Rejected(List.of(new PolicyViolation(field, message, code)));
    }

    private static IssueResult.Rejected verifyCsrSignature(PKCS10CertificationRequest csr) {
        try {
            boolean valid = csr.isSignatureValid(
                    new JcaContentVerifierProviderBuilder()
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                            .build(csr.getSubjectPublicKeyInfo()));
            if (!valid) {
                return rejected("csr.signature", "CSR signature is invalid", ViolationCodes.CSR_SIGNATURE);
            }
            return null;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            return rejected("csr.signature", "CSR signature is invalid", ViolationCodes.CSR_SIGNATURE);
        }
    }

    private static PublicKey subjectPublicKey(PKCS10CertificationRequest csr) {
        try {
            return new JcaPKCS10CertificationRequest(csr).getPublicKey();
        } catch (Exception e) {
            return null;
        }
    }

    private static X500Name issuerName(X509Certificate issuerCertificate) {
        try {
            return new JcaX509CertificateHolder(issuerCertificate).getSubject();
        } catch (CertificateException e) {
            return null;
        }
    }

    private static void copyPolicyExtensions(X509v3CertificateBuilder builder, Extensions extensions)
            throws IOException {
        if (extensions == null) {
            return;
        }
        for (ASN1ObjectIdentifier oid : extensions.getExtensionOIDs()) {
            builder.addExtension(extensions.getExtension(oid));
        }
    }

    private static void addKeyIdentifiers(
            X509v3CertificateBuilder builder,
            PublicKey subjectPublicKey,
            X509Certificate issuerCertificate,
            boolean selfSigned) throws IOException {
        try {
            JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();
            SubjectKeyIdentifier ski = utils.createSubjectKeyIdentifier(subjectPublicKey);
            builder.addExtension(Extension.subjectKeyIdentifier, false, ski);
            AuthorityKeyIdentifier aki = selfSigned
                    ? utils.createAuthorityKeyIdentifier(subjectPublicKey)
                    : utils.createAuthorityKeyIdentifier(new JcaX509CertificateHolder(issuerCertificate));
            builder.addExtension(Extension.authorityKeyIdentifier, false, aki);
        } catch (java.security.NoSuchAlgorithmException | CertificateException e) {
            throw new IOException("Failed to create key identifiers", e);
        }
    }

    private static ContentSigner contentSigner(PublicKey publicKey, PrivateKey privateKey)
            throws OperatorCreationException {
        return new JcaContentSignerBuilder(deriveAlgorithm(publicKey))
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(privateKey);
    }

    private static String deriveAlgorithm(PublicKey publicKey) throws OperatorCreationException {
        return switch (publicKey.getAlgorithm()) {
            case "RSA" -> "SHA256withRSA";
            case "EC" -> {
                int bits = ((ECPublicKey) publicKey).getParams().getCurve().getField().getFieldSize();
                yield switch (bits) {
                    case 256 -> "SHA256withECDSA";
                    case 384 -> "SHA384withECDSA";
                    case 521 -> "SHA512withECDSA";
                    default -> "SHA256withECDSA";
                };
            }
            case "Ed25519" -> "Ed25519";
            case "Ed448" -> "Ed448";
            default -> throw new OperatorCreationException("Unsupported key type: " + publicKey.getAlgorithm());
        };
    }

    private static BigInteger randomSerial() {
        byte[] bytes = new byte[16];
        new SecureRandom().nextBytes(bytes);
        bytes[0] &= 0x7f;
        if (bytes[0] == 0) {
            bytes[0] = 1;
        }
        return new BigInteger(1, bytes);
    }

    private static String toPem(X509Certificate certificate) throws IOException {
        var sw = new StringWriter();
        try (var writer = new JcaPEMWriter(sw)) {
            writer.writeObject(certificate);
        }
        return sw.toString();
    }

    private record RawIssuedCertificateImpl(X509v3CertificateBuilder builder) implements RawIssuedCertificate {
        @Override
        public RawIssuedCertificate addExtension(ASN1ObjectIdentifier oid, boolean critical, ASN1Encodable value) {
            try {
                builder.addExtension(oid, critical, value);
                return this;
            } catch (IOException e) {
                throw new IllegalArgumentException("Failed to add extension " + oid, e);
            }
        }
    }
}
