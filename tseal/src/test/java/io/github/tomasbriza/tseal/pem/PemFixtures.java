package io.github.tomasbriza.tseal.pem;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.junit.jupiter.api.function.Executable;

import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class PemFixtures {

    static final byte[] MESSAGE = "tseal".getBytes(StandardCharsets.UTF_8);

    private PemFixtures() {}

    static void assertSignature(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        Signature signer = Signature.getInstance(signatureAlgorithm(publicKey), BouncyCastleProvider.PROVIDER_NAME);
        signer.initSign(privateKey);
        signer.update(MESSAGE);
        byte[] signature = signer.sign();
        Signature verifier = Signature.getInstance(signatureAlgorithm(publicKey), BouncyCastleProvider.PROVIDER_NAME);
        verifier.initVerify(publicKey);
        verifier.update(MESSAGE);
        assertTrue(verifier.verify(signature));
    }

    static X509Certificate selfSigned(KeyPair keys) throws Exception {
        var builder = new JcaX509v3CertificateBuilder(
                new X500Name("CN=pem"),
                BigInteger.ONE,
                Date.from(Instant.parse("2026-01-01T00:00:00Z")),
                Date.from(Instant.parse("2027-01-01T00:00:00Z")),
                new X500Name("CN=pem"),
                keys.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm(keys.getPublic()))
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keys.getPrivate());
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));
    }

    static String pem(String type, byte[] der) throws Exception {
        var body = new StringWriter();
        try (var writer = new PemWriter(body)) {
            writer.writeObject(new PemObject(type, der));
        }
        return body.toString();
    }

    static String labelled(String label) {
        return "-----BEGIN " + label + "-----\nAAAA\n-----END " + label + "-----\n";
    }

    static void assertRejected(Executable call, String message) {
        assertEquals(message, assertThrows(IllegalArgumentException.class, call).getMessage());
    }

    static boolean posix() {
        return FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
    }

    private static String signatureAlgorithm(PublicKey publicKey) {
        return switch (publicKey.getAlgorithm()) {
            case "RSA" -> "SHA256withRSA";
            case "EC", "ECDSA" -> "SHA256withECDSA";
            case "Ed25519" -> "Ed25519";
            case "Ed448" -> "Ed448";
            default -> throw new IllegalArgumentException(publicKey.getAlgorithm());
        };
    }
}
