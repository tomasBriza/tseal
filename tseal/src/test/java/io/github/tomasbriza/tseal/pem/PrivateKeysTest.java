package io.github.tomasbriza.tseal.pem;

import io.github.tomasbriza.tseal.csr.CsrBuilder;
import io.github.tomasbriza.tseal.key.KeyAlgorithm;
import io.github.tomasbriza.tseal.key.KeyPairFactory;

import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;

import static io.github.tomasbriza.tseal.pem.PemFixtures.assertRejected;
import static io.github.tomasbriza.tseal.pem.PemFixtures.assertSignature;
import static io.github.tomasbriza.tseal.pem.PemFixtures.labelled;
import static io.github.tomasbriza.tseal.pem.PemFixtures.pem;
import static io.github.tomasbriza.tseal.pem.PemFixtures.posix;
import static io.github.tomasbriza.tseal.pem.PemFixtures.selfSigned;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PrivateKeysTest {

    private static final char[] PASSWORD = "s3cret-phrase".toCharArray();

    @ParameterizedTest
    @EnumSource(KeyAlgorithm.class)
    void roundTrips(KeyAlgorithm algorithm) throws Exception {
        KeyPair keys = KeyPairFactory.generate(algorithm);
        String privatePem = PrivateKeys.write(keys.getPrivate());
        assertTrue(privatePem.contains("-----BEGIN PRIVATE KEY-----"));
        assertFalse(privatePem.contains("BEGIN RSA PRIVATE KEY"));
        assertFalse(privatePem.contains("BEGIN EC PRIVATE KEY"));
        assertFalse(privatePem.contains("ENCRYPTED"));

        PrivateKey parsed = PrivateKeys.read(privatePem);
        assertArrayEquals(keys.getPrivate().getEncoded(), parsed.getEncoded());
        assertSignature(parsed, keys.getPublic());
    }

    @Test
    void traditionalRsaPrivateKey_isAccepted() throws Exception {
        KeyPair keys = KeyPairFactory.generate(KeyAlgorithm.RSA_2048);
        RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keys.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keys.getPublic();
        String privatePem = pem("RSA PRIVATE KEY", new RSAPrivateKey(
                privateKey.getModulus(),
                privateKey.getPublicExponent(),
                privateKey.getPrivateExponent(),
                privateKey.getPrimeP(),
                privateKey.getPrimeQ(),
                privateKey.getPrimeExponentP(),
                privateKey.getPrimeExponentQ(),
                privateKey.getCrtCoefficient()).getEncoded());
        assertSignature(PrivateKeys.read(privatePem), publicKey);
    }

    @Test
    void pkcs8Encrypted_roundTrips() throws Exception {
        KeyPair keys = KeyPairFactory.generate(KeyAlgorithm.ED25519);
        String encrypted = pkcs8Encrypted(keys.getPrivate(), PASSWORD);
        assertTrue(encrypted.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----"));

        PrivateKey parsed = PrivateKeys.read(encrypted, PASSWORD);
        assertArrayEquals(keys.getPrivate().getEncoded(), parsed.getEncoded());
        assertRejected(() -> PrivateKeys.read(encrypted),
                "PEM private key is encrypted. Pass a password to PrivateKeys.read.");
        assertRejected(() -> PrivateKeys.read(encrypted, new char[0]),
                "PEM private key is encrypted. The password is empty.");
        assertRejected(() -> PrivateKeys.read(encrypted, null),
                "PEM private key is encrypted. Pass a password to PrivateKeys.read.");

        char[] wrong = "not-the-password".toCharArray();
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> PrivateKeys.read(encrypted, wrong));
        assertEquals("Failed to decrypt the private key. The password may be wrong.", error.getMessage());
        assertNoSecret(error, "not-the-password", encrypted);
    }

    @Test
    void traditionalEncryptedRsaKey_roundTrips() throws Exception {
        KeyPair keys = KeyPairFactory.generate(KeyAlgorithm.RSA_2048);
        String encrypted = traditionalEncrypted(keys.getPrivate(), PASSWORD);
        assertTrue(encrypted.contains("-----BEGIN RSA PRIVATE KEY-----"));
        assertTrue(encrypted.contains("Proc-Type: 4,ENCRYPTED"));

        assertArrayEquals(keys.getPrivate().getEncoded(), PrivateKeys.read(encrypted, PASSWORD).getEncoded());
        assertRejected(() -> PrivateKeys.read(encrypted),
                "PEM private key is encrypted. Pass a password to PrivateKeys.read.");
    }

    @Test
    void passwordOnUnencryptedKey_isRejected() {
        String pem = PrivateKeys.write(KeyPairFactory.generate(KeyAlgorithm.EC_P256).getPrivate());
        assertRejected(() -> PrivateKeys.read(pem, PASSWORD),
                "PEM private key is not encrypted. Do not pass a password.");
        assertRejected(() -> PrivateKeys.read(pem, new char[0]),
                "PEM private key is not encrypted. Do not pass a password.");
    }

    @Test
    void rejectsOtherPemTypes() throws Exception {
        KeyPair keys = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        String certificate = Certificates.write(selfSigned(keys));
        String publicKey = PublicKeys.write(keys.getPublic());
        String csr = CsrBuilder.httpsCsr().dns("app.example").build(keys).pem();

        assertRejected(() -> PrivateKeys.read(certificate), "PEM is a certificate, not a private key.");
        assertRejected(() -> PrivateKeys.read(publicKey), "PEM is a public key, not a private key.");
        assertRejected(() -> PrivateKeys.read(csr), "PEM is a certificate request, not a private key.");
        assertRejected(() -> PrivateKeys.read(labelled("OPENSSH PRIVATE KEY")),
                "OpenSSH private keys are not supported. Convert the key to PKCS#8 (BEGIN PRIVATE KEY).");
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> PrivateKeys.read(labelled("DSA PRIVATE KEY"))).getMessage()
                .startsWith("Failed to parse private key PEM"));
        assertNoSecret(assertThrows(IllegalArgumentException.class, () -> PrivateKeys.read(certificate)),
                "s3cret-phrase", certificate);
    }

    @Test
    void read_rejectsASecondObject() throws Exception {
        KeyPair keys = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        String pem = PrivateKeys.write(keys.getPrivate()) + Certificates.write(selfSigned(keys));
        assertRejected(() -> PrivateKeys.read(pem),
                "PEM contains more than one object. PrivateKeys.read reads a single private key.");
    }

    @Test
    void blankText_isRejected() {
        assertRejected(() -> PrivateKeys.read("not a pem"),
                "PEM has no BEGIN line. Expected a single private key.");
        assertRejected(() -> PrivateKeys.write((PrivateKey) null), "private key is required");
        assertRejected(() -> PrivateKeys.write(KeyPairFactory.generate(KeyAlgorithm.EC_P256).getPrivate(), null),
                "path is required");
    }

    @Test
    void keyWithoutPkcs8Encoding_isRejected() {
        PrivateKey hardware = new PrivateKey() {
            @Override public String getAlgorithm() { return "EC"; }
            @Override public String getFormat() { return null; }
            @Override public byte[] getEncoded() { return null; }
        };
        assertRejected(() -> PrivateKeys.write(hardware),
                "Private key did not provide a PKCS#8 encoding. A hardware key cannot be written as PEM.");

        PrivateKey pkcs1 = new PrivateKey() {
            @Override public String getAlgorithm() { return "RSA"; }
            @Override public String getFormat() { return "PKCS#1"; }
            @Override public byte[] getEncoded() { return new byte[] {1, 2, 3}; }
        };
        assertRejected(() -> PrivateKeys.write(pkcs1),
                "Private key encoding is PKCS#1, not PKCS#8. PrivateKeys.write writes BEGIN PRIVATE KEY.");
    }

    @Test
    void files_roundTripAndRejectBadPaths(@TempDir Path dir) throws Exception {
        KeyPair keys = KeyPairFactory.generate(KeyAlgorithm.EC_P384);
        Path keyPath = dir.resolve("app.key");
        PrivateKeys.write(keys.getPrivate(), keyPath);
        assertArrayEquals(keys.getPrivate().getEncoded(), PrivateKeys.read(keyPath).getEncoded());
        assertEquals("PEM file already exists: " + keyPath,
                assertThrows(IllegalArgumentException.class,
                        () -> PrivateKeys.write(keys.getPrivate(), keyPath)).getMessage());
        assertArrayEquals(keys.getPrivate().getEncoded(), PrivateKeys.read(keyPath).getEncoded());
        if (posix()) {
            assertEquals(Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
                    Files.getPosixFilePermissions(keyPath));
            assertFalse(Files.getPosixFilePermissions(keyPath).contains(PosixFilePermission.GROUP_READ));
        }

        Path certPath = dir.resolve("app.crt");
        Certificates.write(selfSigned(keys), certPath);
        assertEquals("PEM is a certificate, not a private key: " + certPath,
                assertThrows(IllegalArgumentException.class, () -> PrivateKeys.read(certPath)).getMessage());

        Path nested = dir.resolve("missing-dir").resolve("key.pem");
        assertEquals("Directory does not exist: " + nested.toAbsolutePath().getParent(),
                assertThrows(IllegalArgumentException.class,
                        () -> PrivateKeys.write(keys.getPrivate(), nested)).getMessage());

        Path huge = dir.resolve("huge.pem");
        Files.write(huge, new byte[PemSyntax.MAX_BYTES + 1]);
        assertEquals("PEM file is larger than 1 MiB: " + huge,
                assertThrows(IllegalArgumentException.class, () -> PrivateKeys.read(huge)).getMessage());

        Path link = dir.resolve("key.link");
        Files.createSymbolicLink(link, keyPath);
        assertArrayEquals(keys.getPrivate().getEncoded(), PrivateKeys.read(link).getEncoded());
        assertEquals("PEM path is a symbolic link: " + link,
                assertThrows(IllegalArgumentException.class,
                        () -> PrivateKeys.write(keys.getPrivate(), link)).getMessage());
    }

    private static String pkcs8Encrypted(PrivateKey privateKey, char[] password) throws Exception {
        var encryptor = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.AES_256_CBC)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .setPassword(password)
                .build();
        var body = new StringWriter();
        try (var writer = new JcaPEMWriter(body)) {
            writer.writeObject(new JcaPKCS8Generator(privateKey, encryptor));
        }
        return body.toString();
    }

    private static String traditionalEncrypted(PrivateKey privateKey, char[] password) throws Exception {
        var encryptor = new JcePEMEncryptorBuilder("AES-256-CBC")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(password);
        var body = new StringWriter();
        try (var writer = new JcaPEMWriter(body)) {
            writer.writeObject(privateKey, encryptor);
        }
        return body.toString();
    }

    private static void assertNoSecret(Throwable error, String secret, String pemText) {
        String body = pemText.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replace("-----BEGIN ENCRYPTED PRIVATE KEY-----", "")
                .replace("-----END ENCRYPTED PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        String snippet = body.length() > 24 ? body.substring(0, 24) : body;
        for (Throwable current = error; current != null; current = current.getCause()) {
            if (current.getMessage() != null) {
                assertFalse(current.getMessage().contains(secret), current.getMessage());
                assertFalse(current.getMessage().contains(snippet), current.getMessage());
            }
        }
    }
}
