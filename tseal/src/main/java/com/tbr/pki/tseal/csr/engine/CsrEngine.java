package com.tbr.pki.tseal.csr.engine;

import com.tbr.pki.tseal.csr.CsrResult;
import com.tbr.pki.tseal.csr.Oids;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.IOException;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPublicKey;

public class CsrEngine {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private CsrEngine() {}

    public static CsrResult build(CsrAccumulator acc, PublicKey publicKey, PrivateKey privateKey, ContentSigner explicitSigner) {
        try {
            finalizeExtensions(acc, publicKey);

            var subject = acc.subjectBuilder.build();
            PKCS10CertificationRequestBuilder builder =
                    new JcaPKCS10CertificationRequestBuilder(subject, publicKey);

            if (!acc.extensionsGenerator.isEmpty()) {
                builder.addAttribute(
                        PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                        acc.extensionsGenerator.generate());
            }

            for (var attr : acc.extraAttributes) {
                builder.addAttribute(attr.oid(), attr.value());
            }

            ContentSigner signer = resolveSigner(acc, publicKey, privateKey, explicitSigner);
            PKCS10CertificationRequest csr = builder.build(signer);

            return new CsrResult(csr, toPem(csr));
        } catch (OperatorCreationException | IOException e) {
            throw new IllegalStateException("CSR build failed", e);
        }
    }

    private static void finalizeExtensions(CsrAccumulator acc, PublicKey publicKey) {
        if (acc.adaptiveKeyUsage) {
            int bits = isRsa(publicKey)
                    ? KeyUsage.digitalSignature | KeyUsage.keyEncipherment
                    : KeyUsage.digitalSignature;
            acc.addExtension(Extension.keyUsage, true, new KeyUsage(bits));
        }

        if (!acc.sanEntries.isEmpty()) {
            acc.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(acc.sanEntries.toArray(new GeneralName[0])));
        }

        if (acc.requestedValidity != null) {
            acc.addExtension(Oids.REQUESTED_VALIDITY, false,
                    new ASN1Integer(acc.requestedValidity.toSeconds()));
        }
    }

    private static ContentSigner resolveSigner(
            CsrAccumulator acc, PublicKey publicKey, PrivateKey privateKey, ContentSigner explicitSigner)
            throws OperatorCreationException {
        if (explicitSigner != null) return explicitSigner;
        if (acc.contentSignerOverride != null) return acc.contentSignerOverride;

        String alg = acc.signatureAlgorithmOverride != null
                ? acc.signatureAlgorithmOverride
                : deriveAlgorithm(publicKey);
        return new JcaContentSignerBuilder(alg)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(privateKey);
    }

    private static String deriveAlgorithm(PublicKey publicKey) {
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
            default -> throw new IllegalArgumentException("Unsupported key type: " + publicKey.getAlgorithm());
        };
    }

    private static boolean isRsa(PublicKey publicKey) {
        return "RSA".equals(publicKey.getAlgorithm());
    }

    private static String toPem(PKCS10CertificationRequest csr) throws IOException {
        var sw = new StringWriter();
        try (var writer = new JcaPEMWriter(sw)) {
            writer.writeObject(csr);
        }
        return sw.toString();
    }
}
