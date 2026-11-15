package io.github.tomasbriza.tseal.pem;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.IOException;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.List;

/**
 * Read and write one public key as PEM.
 *
 * <p>A certificate is rejected. Read it with {@link Certificates#read} and call
 * {@link java.security.cert.Certificate#getPublicKey()}. A second PEM object is rejected.
 */
public final class PublicKeys {

    private PublicKeys() {}

    /** Reads one {@code PUBLIC KEY} or {@code RSA PUBLIC KEY}. */
    public static PublicKey read(String pem) {
        String text = PemSyntax.text(pem, "public key");
        List<String> labels = PemSyntax.labels(text);
        if (labels.isEmpty()) {
            throw new IllegalArgumentException("PEM has no BEGIN line. Expected a single public key.");
        }
        if (labels.size() > 1) {
            throw new IllegalArgumentException(
                    "PEM contains more than one object. PublicKeys.read reads a single public key.");
        }
        String label = labels.getFirst();
        if (!PEMParser.TYPE_PUBLIC_KEY.equals(label) && !PEMParser.TYPE_RSA_PUBLIC_KEY.equals(label)) {
            throw PemSyntax.wrongType(label, "a public key");
        }
        List<Object> objects = PemSyntax.parse(text, "public key");
        if (objects.size() != 1) {
            throw new IllegalArgumentException("Failed to parse public key PEM");
        }
        return switch (objects.getFirst()) {
            case SubjectPublicKeyInfo keyInfo -> toPublicKey(keyInfo);
            case org.bouncycastle.asn1.pkcs.RSAPublicKey rsa -> toPublicKey(rsa);
            default -> throw new IllegalArgumentException(
                    "PEM is labelled " + label + " but did not contain a public key.");
        };
    }

    /** Reads one public key from a UTF-8 PEM file. */
    public static PublicKey read(Path path) {
        return PemFiles.parse(path, PublicKeys::read);
    }

    /** Writes one public key as {@code BEGIN PUBLIC KEY}. */
    public static String write(PublicKey publicKey) {
        if (publicKey == null) {
            throw new IllegalArgumentException("public key is required");
        }
        byte[] encoded = publicKey.getEncoded();
        if (encoded == null || encoded.length == 0) {
            throw new IllegalArgumentException("Public key did not provide an X.509 encoding.");
        }
        String format = publicKey.getFormat();
        if (format != null && !"X.509".equalsIgnoreCase(format)) {
            throw new IllegalArgumentException(
                    "Public key encoding is " + format + ", not X.509. PublicKeys.write writes BEGIN PUBLIC KEY.");
        }
        try {
            SubjectPublicKeyInfo.getInstance(encoded);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Public key encoding is not X.509 SubjectPublicKeyInfo.", e);
        }
        return PemSyntax.encode("PUBLIC KEY", encoded);
    }

    /**
     * Writes one public key. Fails if {@code path} exists or is a symbolic link.
     * On POSIX the file mode is {@code 0644}.
     */
    public static void write(PublicKey publicKey, Path path) {
        PemFiles.write(path, write(publicKey), false);
    }

    private static PublicKey toPublicKey(SubjectPublicKeyInfo keyInfo) {
        try {
            return converter().getPublicKey(keyInfo);
        } catch (PEMException e) {
            throw new IllegalArgumentException("Failed to read public key PEM", e);
        }
    }

    private static PublicKey toPublicKey(org.bouncycastle.asn1.pkcs.RSAPublicKey rsa) {
        try {
            var keyInfo = new SubjectPublicKeyInfo(
                    new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
                    rsa.getEncoded());
            return toPublicKey(keyInfo);
        } catch (IOException e) {
            throw new IllegalArgumentException("Failed to read public key PEM", e);
        }
    }

    private static JcaPEMKeyConverter converter() {
        return new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
    }
}
