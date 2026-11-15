package io.github.tomasbriza.tseal.pem;

import io.github.tomasbriza.tseal.key.KeyAlgorithm;
import io.github.tomasbriza.tseal.key.KeyPairFactory;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

import static io.github.tomasbriza.tseal.pem.PemFixtures.assertRejected;
import static io.github.tomasbriza.tseal.pem.PemFixtures.assertSignature;
import static io.github.tomasbriza.tseal.pem.PemFixtures.labelled;
import static io.github.tomasbriza.tseal.pem.PemFixtures.pem;
import static io.github.tomasbriza.tseal.pem.PemFixtures.posix;
import static io.github.tomasbriza.tseal.pem.PemFixtures.selfSigned;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PublicKeysTest {

    @ParameterizedTest
    @EnumSource(KeyAlgorithm.class)
    void roundTrips(KeyAlgorithm algorithm) throws Exception {
        KeyPair keys = KeyPairFactory.generate(algorithm);
        String publicPem = PublicKeys.write(keys.getPublic());
        assertTrue(publicPem.contains("-----BEGIN PUBLIC KEY-----"));
        PublicKey parsed = PublicKeys.read(publicPem);
        assertArrayEquals(keys.getPublic().getEncoded(), parsed.getEncoded());
        assertSignature(keys.getPrivate(), parsed);
    }

    @Test
    void traditionalRsaPublicKey_isAccepted() throws Exception {
        KeyPair keys = KeyPairFactory.generate(KeyAlgorithm.RSA_2048);
        RSAPublicKey publicKey = (RSAPublicKey) keys.getPublic();
        String publicPem = pem("RSA PUBLIC KEY", new org.bouncycastle.asn1.pkcs.RSAPublicKey(
                publicKey.getModulus(), publicKey.getPublicExponent()).getEncoded());
        assertArrayEquals(publicKey.getEncoded(), PublicKeys.read(publicPem).getEncoded());
    }

    @Test
    void rejectsOtherPemTypes() throws Exception {
        KeyPair keys = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        String certificate = Certificates.write(selfSigned(keys));
        String privateKey = PrivateKeys.write(keys.getPrivate());

        assertRejected(() -> PublicKeys.read(certificate), "PEM is a certificate, not a public key.");
        assertRejected(() -> PublicKeys.read(privateKey), "PEM is a private key, not a public key.");
        assertRejected(() -> PublicKeys.read(labelled("ENCRYPTED PRIVATE KEY")),
                "PEM is an encrypted private key, not a public key.");
    }

    @Test
    void blankText_isRejected() {
        assertRejected(() -> PublicKeys.read("  \n"), "public key PEM must be non-blank");
        assertRejected(() -> PublicKeys.write(null), "public key is required");
    }

    @Test
    void encodingThatIsNotSubjectPublicKeyInfo_isRejected() {
        PublicKey raw = new PublicKey() {
            @Override public String getAlgorithm() { return "RSA"; }
            @Override public String getFormat() { return "X.509"; }
            @Override public byte[] getEncoded() { return new byte[] {1, 2, 3}; }
        };
        assertTrue(assertThrows(IllegalArgumentException.class, () -> PublicKeys.write(raw)).getMessage()
                .startsWith("Public key encoding is not X.509 SubjectPublicKeyInfo."));
    }

    @Test
    void files_roundTripAndRejectBadPaths(@TempDir Path dir) throws Exception {
        KeyPair keys = KeyPairFactory.generate(KeyAlgorithm.EC_P384);
        Path publicPath = dir.resolve("app.pub");
        PublicKeys.write(keys.getPublic(), publicPath);
        assertArrayEquals(keys.getPublic().getEncoded(), PublicKeys.read(publicPath).getEncoded());
        if (posix()) {
            assertTrue(Files.getPosixFilePermissions(publicPath).contains(PosixFilePermission.GROUP_READ));
            assertTrue(Files.getPosixFilePermissions(publicPath).contains(PosixFilePermission.OTHERS_READ));
        }

        assertEquals("PEM path is a directory: " + dir,
                assertThrows(IllegalArgumentException.class, () -> PublicKeys.read(dir)).getMessage());

        Path parentFile = dir.resolve("not-a-directory");
        Files.writeString(parentFile, "x");
        Path child = parentFile.resolve("key.pem");
        assertEquals("PEM parent is not a directory: " + child.toAbsolutePath().getParent(),
                assertThrows(IllegalArgumentException.class,
                        () -> PublicKeys.write(keys.getPublic(), child)).getMessage());
    }
}
