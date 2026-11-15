package io.github.tomasbriza.tseal.pem;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.file.Path;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** PEM text checks shared by {@link Certificates}, {@link PublicKeys}, and {@link PrivateKeys}. */
final class PemSyntax {

    static final int MAX_BYTES = 1024 * 1024;

    static final String OPENSSH_PRIVATE_KEY = "OPENSSH PRIVATE KEY";

    private static final Pattern BEGIN_LINE = Pattern.compile("-----BEGIN ([A-Z0-9 ]+)-----");

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private PemSyntax() {}

    /** Strips a leading BOM and rejects blank or oversized text. */
    static String text(String pem, String kind) {
        if (pem != null && pem.startsWith("\uFEFF")) {
            pem = pem.substring(1);
        }
        if (pem == null || pem.isBlank()) {
            throw new IllegalArgumentException(kind + " PEM must be non-blank");
        }
        if (pem.length() > MAX_BYTES || utf8Length(pem) > MAX_BYTES) {
            throw new IllegalArgumentException(kind + " PEM is larger than 1 MiB");
        }
        return pem;
    }

    static List<String> labels(String pem) {
        var labels = new ArrayList<String>();
        Matcher matcher = BEGIN_LINE.matcher(pem);
        while (matcher.find()) {
            labels.add(matcher.group(1));
        }
        return labels;
    }

    static List<Object> parse(String pem, String kind) {
        var parsed = new ArrayList<Object>();
        try (var parser = new PEMParser(new StringReader(pem))) {
            Object object;
            while ((object = parser.readObject()) != null) {
                parsed.add(object);
            }
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (IOException e) {
            throw new IllegalArgumentException("Failed to parse " + kind + " PEM", e);
        }
        if (parsed.isEmpty()) {
            throw new IllegalArgumentException("Failed to parse " + kind + " PEM");
        }
        return parsed;
    }

    static IllegalArgumentException wrongType(String label, String expected) {
        return typeMismatch("PEM is ", label, expected);
    }

    static IllegalArgumentException wrongObject(int number, String label, String expected) {
        return typeMismatch("PEM object " + number + " is ", label, expected);
    }

    static IllegalArgumentException at(IllegalArgumentException error, Path path) {
        String message = error.getMessage();
        if (message.endsWith(".")) {
            message = message.substring(0, message.length() - 1);
        }
        return new IllegalArgumentException(message + ": " + path, error.getCause());
    }

    static String encode(String type, byte[] der) {
        var body = new StringWriter();
        try (var writer = new PemWriter(body)) {
            writer.writeObject(new PemObject(type, der));
        } catch (IOException e) {
            throw new IllegalStateException("Failed to write PEM", e);
        }
        return body.toString();
    }

    private static IllegalArgumentException typeMismatch(String prefix, String label, String expected) {
        String found = switch (label) {
            case PEMParser.TYPE_CERTIFICATE, PEMParser.TYPE_X509_CERTIFICATE -> "a certificate";
            case PEMParser.TYPE_TRUSTED_CERTIFICATE -> "a trusted certificate";
            case PEMParser.TYPE_ATTRIBUTE_CERTIFICATE -> "an attribute certificate";
            case PEMParser.TYPE_CERTIFICATE_REQUEST, PEMParser.TYPE_NEW_CERTIFICATE_REQUEST ->
                    "a certificate request";
            case PEMParser.TYPE_X509_CRL -> "a CRL";
            case PEMParser.TYPE_PKCS7, PEMParser.TYPE_CMS -> "PKCS#7";
            case PEMParser.TYPE_PUBLIC_KEY, PEMParser.TYPE_RSA_PUBLIC_KEY -> "a public key";
            case PEMParser.TYPE_PRIVATE_KEY, PEMParser.TYPE_RSA_PRIVATE_KEY, PEMParser.TYPE_EC_PRIVATE_KEY,
                    PEMParser.TYPE_DSA_PRIVATE_KEY -> "a private key";
            case PEMParser.TYPE_ENCRYPTED_PRIVATE_KEY -> "an encrypted private key";
            case OPENSSH_PRIVATE_KEY -> "an OpenSSH private key";
            default -> "a PEM object labelled " + label;
        };
        if ("PKCS#7".equals(found)) {
            return new IllegalArgumentException(prefix + "PKCS#7, not " + expected + ".");
        }
        return new IllegalArgumentException(prefix + found + ", not " + expected + ".");
    }

    private static int utf8Length(String pem) {
        int bytes = 0;
        for (int i = 0; i < pem.length(); i++) {
            char c = pem.charAt(i);
            if (c <= 0x7F) {
                bytes++;
            } else if (c <= 0x7FF) {
                bytes += 2;
            } else if (Character.isHighSurrogate(c)) {
                bytes += 4;
                i++;
            } else {
                bytes += 3;
            }
            if (bytes > MAX_BYTES) {
                return bytes;
            }
        }
        return bytes;
    }
}
