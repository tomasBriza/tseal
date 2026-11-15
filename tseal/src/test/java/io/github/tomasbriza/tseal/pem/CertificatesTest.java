package io.github.tomasbriza.tseal.pem;

import io.github.tomasbriza.tseal.csr.CsrBuilder;
import io.github.tomasbriza.tseal.issue.CertificateIssuer;
import io.github.tomasbriza.tseal.issue.IssueResult;
import io.github.tomasbriza.tseal.key.KeyAlgorithm;
import io.github.tomasbriza.tseal.key.KeyPairFactory;
import io.github.tomasbriza.tseal.policy.PolicyBuilder;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static io.github.tomasbriza.tseal.pem.PemFixtures.assertRejected;
import static io.github.tomasbriza.tseal.pem.PemFixtures.labelled;
import static io.github.tomasbriza.tseal.pem.PemFixtures.posix;
import static io.github.tomasbriza.tseal.pem.PemFixtures.selfSigned;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CertificatesTest {

    @Test
    void roundTrips() throws Exception {
        KeyPair keys = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        X509Certificate certificate = selfSigned(keys);
        String pem = Certificates.write(certificate);
        assertTrue(pem.contains("-----BEGIN CERTIFICATE-----"));
        assertEquals(certificate, Certificates.read(pem));
        assertEquals(certificate, Certificates.read("\n" + pem.replace("\n", "\r\n") + "\n"));
        assertEquals(certificate, Certificates.read("\uFEFF" + pem));

        String legacy = pem.replace("BEGIN CERTIFICATE", "BEGIN X509 CERTIFICATE")
                .replace("END CERTIFICATE", "END X509 CERTIFICATE");
        assertEquals(certificate, Certificates.read(legacy));
        assertEquals(List.of(certificate), Certificates.readChain(pem));
        assertEquals(pem, Certificates.writeChain(List.of(certificate)));
    }

    @Test
    void issuedCertificatePem_roundTrips() {
        KeyPair keys = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        var csr = CsrBuilder.signingCsr().commonName("Pem Root").build(keys);
        IssueResult.Issued issued = assertInstanceOf(IssueResult.Issued.class, CertificateIssuer.issue()
                .csr(csr.request())
                .policy(PolicyBuilder.signingPolicy().build())
                .selfSigned(keys)
                .issue());
        assertEquals(issued.certificate(), Certificates.read(issued.pem()));
    }

    @Test
    void rejectsOtherPemTypes() throws Exception {
        KeyPair keys = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        String publicKey = PublicKeys.write(keys.getPublic());
        String privateKey = PrivateKeys.write(keys.getPrivate());
        String csr = CsrBuilder.httpsCsr().dns("app.example").build(keys).pem();

        assertRejected(() -> Certificates.read(privateKey), "PEM is a private key, not a certificate.");
        assertRejected(() -> Certificates.read(publicKey), "PEM is a public key, not a certificate.");
        assertRejected(() -> Certificates.read(csr), "PEM is a certificate request, not a certificate.");
        assertRejected(() -> Certificates.read(labelled("NEW CERTIFICATE REQUEST")),
                "PEM is a certificate request, not a certificate.");
        assertRejected(() -> Certificates.read(labelled("X509 CRL")), "PEM is a CRL, not a certificate.");
        assertRejected(() -> Certificates.read(labelled("PKCS7")), "PEM is PKCS#7, not a certificate.");
        assertRejected(() -> Certificates.read(labelled("CMS")), "PEM is PKCS#7, not a certificate.");
        assertRejected(() -> Certificates.read(labelled("TRUSTED CERTIFICATE")),
                "PEM is a trusted certificate. Certificates.read accepts only an X.509 certificate.");
        assertRejected(() -> Certificates.read(labelled("ATTRIBUTE CERTIFICATE")),
                "PEM is an attribute certificate. Certificates.read accepts only an X.509 certificate.");
        assertRejected(() -> Certificates.read(labelled("OPENSSH PRIVATE KEY")),
                "PEM is an OpenSSH private key, not a certificate.");
        assertRejected(() -> Certificates.read(labelled("EC PARAMETERS")),
                "PEM is a PEM object labelled EC PARAMETERS, not a certificate.");
    }

    @Test
    void read_rejectsAChain() throws Exception {
        String certificate = Certificates.write(selfSigned(KeyPairFactory.generate(KeyAlgorithm.EC_P256)));
        assertRejected(() -> Certificates.read(certificate + certificate),
                "PEM contains more than one object. Certificates.read reads a single certificate. Use Certificates.readChain for a chain.");
    }

    @Test
    void chain_keepsFileOrder(@TempDir Path dir) throws Exception {
        X509Certificate leaf = selfSigned(KeyPairFactory.generate(KeyAlgorithm.EC_P256));
        X509Certificate intermediate = selfSigned(KeyPairFactory.generate(KeyAlgorithm.EC_P384));
        X509Certificate root = selfSigned(KeyPairFactory.generate(KeyAlgorithm.ED25519));
        List<X509Certificate> chain = List.of(leaf, intermediate, root);

        String pem = Certificates.writeChain(chain);
        assertEquals(chain, Certificates.readChain(pem));
        assertEquals(chain, Certificates.readChain("\n" + pem + "\n"));
        assertRejected(() -> Certificates.read(pem),
                "PEM contains more than one object. Certificates.read reads a single certificate. Use Certificates.readChain for a chain.");

        Path path = dir.resolve("fullchain.pem");
        Certificates.writeChain(chain, path);
        assertEquals(chain, Certificates.readChain(path));
        if (posix()) {
            assertTrue(Files.getPosixFilePermissions(path).contains(PosixFilePermission.GROUP_READ));
            assertTrue(Files.getPosixFilePermissions(path).contains(PosixFilePermission.OTHERS_READ));
        }
        assertEquals("PEM file already exists: " + path,
                assertThrows(IllegalArgumentException.class, () -> Certificates.writeChain(chain, path)).getMessage());

        String withKey = Certificates.write(leaf)
                + PrivateKeys.write(KeyPairFactory.generate(KeyAlgorithm.EC_P256).getPrivate())
                + Certificates.write(root);
        assertRejected(() -> Certificates.readChain(withKey),
                "PEM object 2 is a private key, not a certificate.");
        Path mixed = dir.resolve("mixed.pem");
        Files.writeString(mixed, withKey);
        assertEquals("PEM object 2 is a private key, not a certificate: " + mixed,
                assertThrows(IllegalArgumentException.class, () -> Certificates.readChain(mixed)).getMessage());

        assertRejected(() -> Certificates.readChain(Certificates.write(leaf) + labelled("TRUSTED CERTIFICATE")),
                "PEM object 2 is a trusted certificate. Certificates.readChain accepts only an X.509 certificate.");
        assertRejected(() -> Certificates.readChain(labelled("PRIVATE KEY")),
                "PEM object 1 is a private key, not a certificate.");
        assertRejected(() -> Certificates.readChain((String) null), "certificate chain PEM must be non-blank");
        assertRejected(() -> Certificates.readChain("no begin"),
                "PEM has no BEGIN line. Expected one or more certificates.");
        assertRejected(() -> Certificates.writeChain(List.of()), "certificate chain must not be empty");
        assertRejected(() -> Certificates.writeChain((List<X509Certificate>) null), "certificate chain is required");
        var hole = new ArrayList<X509Certificate>();
        hole.add(leaf);
        hole.add(null);
        assertRejected(() -> Certificates.writeChain(hole),
                "certificate chain contains a null certificate at index 1");
    }

    @Test
    void blankAndOversizedText_areRejected() {
        assertRejected(() -> Certificates.read((String) null), "certificate PEM must be non-blank");
        assertRejected(() -> Certificates.read("A".repeat(PemSyntax.MAX_BYTES + 1)),
                "certificate PEM is larger than 1 MiB");
        assertRejected(() -> Certificates.read("é".repeat(PemSyntax.MAX_BYTES / 2 + 1)),
                "certificate PEM is larger than 1 MiB");
        assertRejected(() -> Certificates.read("é".repeat(PemSyntax.MAX_BYTES / 2)),
                "PEM has no BEGIN line. Expected a single certificate.");
        assertRejected(() -> Certificates.write((X509Certificate) null), "certificate is required");
        assertRejected(() -> Certificates.read((Path) null), "path is required");
    }

    @Test
    void files_roundTripAndRejectBadPaths(@TempDir Path dir) throws Exception {
        X509Certificate certificate = selfSigned(KeyPairFactory.generate(KeyAlgorithm.EC_P256));
        Path certPath = dir.resolve("app.crt");
        Certificates.write(certificate, certPath);
        assertEquals(certificate, Certificates.read(certPath));
        if (posix()) {
            assertTrue(Files.getPosixFilePermissions(certPath).contains(PosixFilePermission.GROUP_READ));
            assertTrue(Files.getPosixFilePermissions(certPath).contains(PosixFilePermission.OTHERS_READ));
        }

        Path missing = dir.resolve("missing.pem");
        assertEquals("PEM file does not exist: " + missing,
                assertThrows(IllegalArgumentException.class, () -> Certificates.read(missing)).getMessage());
        assertEquals("PEM path is a directory: " + dir,
                assertThrows(IllegalArgumentException.class,
                        () -> Certificates.write(certificate, dir)).getMessage());

        Path empty = dir.resolve("empty.pem");
        Files.writeString(empty, "");
        assertEquals("PEM file is empty: " + empty,
                assertThrows(IllegalArgumentException.class, () -> Certificates.read(empty)).getMessage());

        Path binary = dir.resolve("binary.pem");
        Files.write(binary, new byte[] {(byte) 0xff, (byte) 0xfe});
        assertEquals("PEM file is not UTF-8: " + binary,
                assertThrows(IllegalArgumentException.class, () -> Certificates.read(binary)).getMessage());
    }
}
