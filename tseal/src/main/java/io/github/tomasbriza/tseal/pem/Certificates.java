package io.github.tomasbriza.tseal.pem;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;

import java.nio.file.Path;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Read and write X.509 certificates as PEM.
 *
 * <p>{@link #read} accepts one certificate. {@link #readChain} accepts one or more, in file order.
 * Neither method checks that the certificates chain or are trusted. A private key, a second
 * object passed to {@code read}, or a non-certificate in a chain is {@link IllegalArgumentException}.
 * The message names the PEM object that was found.
 */
public final class Certificates {

    private static final Set<String> CERTIFICATE_LABELS = Set.of(
            PEMParser.TYPE_CERTIFICATE,
            PEMParser.TYPE_X509_CERTIFICATE);

    private Certificates() {}

    /** Reads one {@code CERTIFICATE} or {@code X509 CERTIFICATE}. */
    public static X509Certificate read(String pem) {
        Parsed parsed = one(
                pem,
                "certificate",
                "Certificates.read reads a single certificate. Use Certificates.readChain for a chain.",
                label -> rejectUnlessCertificate(label, 0, "Certificates.read"));
        return certificate(parsed.label(), parsed.object(), 0, "Certificates.read");
    }

    /** Reads one certificate from a UTF-8 PEM file. */
    public static X509Certificate read(Path path) {
        return PemFiles.parse(path, Certificates::read);
    }

    /**
     * Reads every certificate in {@code pem}, in file order.
     * One certificate is a chain of one. A non-certificate is rejected.
     */
    public static List<X509Certificate> readChain(String pem) {
        String text = PemSyntax.text(pem, "certificate chain");
        List<String> labels = PemSyntax.labels(text);
        if (labels.isEmpty()) {
            throw new IllegalArgumentException("PEM has no BEGIN line. Expected one or more certificates.");
        }
        for (int i = 0; i < labels.size(); i++) {
            rejectUnlessCertificate(labels.get(i), i + 1, "Certificates.readChain");
        }
        List<Object> objects = PemSyntax.parse(text, "certificate chain");
        if (objects.size() != labels.size()) {
            throw new IllegalArgumentException("Failed to parse certificate chain PEM");
        }
        var chain = new ArrayList<X509Certificate>(labels.size());
        for (int i = 0; i < labels.size(); i++) {
            chain.add(certificate(labels.get(i), objects.get(i), i + 1, "Certificates.readChain"));
        }
        return List.copyOf(chain);
    }

    /** Reads a certificate chain from a UTF-8 PEM file. Order is the file order. */
    public static List<X509Certificate> readChain(Path path) {
        return PemFiles.parse(path, Certificates::readChain);
    }

    /** Writes one certificate as {@code BEGIN CERTIFICATE}. */
    public static String write(X509Certificate certificate) {
        if (certificate == null) {
            throw new IllegalArgumentException("certificate is required");
        }
        try {
            return PemSyntax.encode("CERTIFICATE", certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new IllegalArgumentException("Failed to encode certificate", e);
        }
    }

    /**
     * Writes one certificate. Fails if {@code path} exists or is a symbolic link.
     * On POSIX the file mode is {@code 0644}.
     */
    public static void write(X509Certificate certificate, Path path) {
        PemFiles.write(path, write(certificate), false);
    }

    /**
     * Writes {@code certificates} in list order, one PEM block each.
     * The list must be non-empty and contain no null entry.
     */
    public static String writeChain(List<X509Certificate> certificates) {
        if (certificates == null) {
            throw new IllegalArgumentException("certificate chain is required");
        }
        if (certificates.isEmpty()) {
            throw new IllegalArgumentException("certificate chain must not be empty");
        }
        var pem = new StringBuilder();
        for (int i = 0; i < certificates.size(); i++) {
            X509Certificate certificate = certificates.get(i);
            if (certificate == null) {
                throw new IllegalArgumentException(
                        "certificate chain contains a null certificate at index " + i);
            }
            pem.append(write(certificate));
        }
        return pem.toString();
    }

    /**
     * Writes a certificate chain. Fails if {@code path} exists or is a symbolic link.
     * On POSIX the file mode is {@code 0644}.
     */
    public static void writeChain(List<X509Certificate> certificates, Path path) {
        PemFiles.write(path, writeChain(certificates), false);
    }

    private static Parsed one(String pem, String kind, String multiple, Consumer<String> checkLabel) {
        String text = PemSyntax.text(pem, kind);
        List<String> labels = PemSyntax.labels(text);
        if (labels.isEmpty()) {
            throw new IllegalArgumentException("PEM has no BEGIN line. Expected a single " + kind + ".");
        }
        if (labels.size() > 1) {
            throw new IllegalArgumentException("PEM contains more than one object. " + multiple);
        }
        checkLabel.accept(labels.getFirst());
        List<Object> objects = PemSyntax.parse(text, kind);
        if (objects.size() != 1) {
            throw new IllegalArgumentException("Failed to parse " + kind + " PEM");
        }
        return new Parsed(labels.getFirst(), objects.getFirst());
    }

    private static void rejectUnlessCertificate(String label, int number, String reader) {
        if (CERTIFICATE_LABELS.contains(label)) {
            return;
        }
        if (PEMParser.TYPE_TRUSTED_CERTIFICATE.equals(label)) {
            throw trusted(number, reader);
        }
        if (PEMParser.TYPE_ATTRIBUTE_CERTIFICATE.equals(label)) {
            throw attribute(number, reader);
        }
        throw number < 1
                ? PemSyntax.wrongType(label, "a certificate")
                : PemSyntax.wrongObject(number, label, "a certificate");
    }

    private static X509Certificate certificate(String label, Object parsed, int number, String reader) {
        rejectUnlessCertificate(label, number, reader);
        if (parsed instanceof X509CertificateHolder holder) {
            return toCertificate(holder);
        }
        String where = number < 1 ? "PEM is labelled " : "PEM object " + number + " is labelled ";
        throw new IllegalArgumentException(where + label + " but did not contain an X.509 certificate.");
    }

    private static IllegalArgumentException trusted(int number, String reader) {
        String what = number < 1
                ? "PEM is a trusted certificate. "
                : "PEM object " + number + " is a trusted certificate. ";
        return new IllegalArgumentException(what + reader + " accepts only an X.509 certificate.");
    }

    private static IllegalArgumentException attribute(int number, String reader) {
        String what = number < 1
                ? "PEM is an attribute certificate. "
                : "PEM object " + number + " is an attribute certificate. ";
        return new IllegalArgumentException(what + reader + " accepts only an X.509 certificate.");
    }

    private static X509Certificate toCertificate(X509CertificateHolder holder) {
        try {
            return new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(holder);
        } catch (CertificateException e) {
            throw new IllegalArgumentException("Failed to read certificate PEM", e);
        }
    }

    private record Parsed(String label, Object object) {}
}
