package io.github.tomasbriza.tseal.pem;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;

import java.io.IOException;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.util.List;
import java.util.Set;

/**
 * Read and write one private key as PEM.
 *
 * <p>Reads PKCS#8, encrypted PKCS#8, PKCS#1 RSA, SEC1 EC, and traditional DSA.
 * Writes unencrypted PKCS#8 ({@code BEGIN PRIVATE KEY}). {@link #read(String)} rejects an
 * encrypted key. {@link #read(String, char[])} requires a non-empty password for an encrypted
 * key and rejects a password for an unencrypted key. The password array is not stored, and it
 * is not included in the exception message.
 *
 * <p>OpenSSH keys are rejected. A second PEM object is rejected.
 * {@link #write(PrivateKey, Path)} fails when the path exists and, on POSIX, sets mode {@code 0600}.
 */
public final class PrivateKeys {

    private static final Set<String> PRIVATE_KEY_LABELS = Set.of(
            PEMParser.TYPE_PRIVATE_KEY,
            PEMParser.TYPE_ENCRYPTED_PRIVATE_KEY,
            PEMParser.TYPE_RSA_PRIVATE_KEY,
            PEMParser.TYPE_EC_PRIVATE_KEY,
            PEMParser.TYPE_DSA_PRIVATE_KEY);

    private PrivateKeys() {}

    /** Reads one unencrypted private key. An encrypted key is rejected. */
    public static PrivateKey read(String pem) {
        return read(pem, null, false);
    }

    /** Reads one unencrypted private key from a UTF-8 PEM file. */
    public static PrivateKey read(Path path) {
        return PemFiles.parse(path, PrivateKeys::read);
    }

    /**
     * Reads one private key. A non-empty {@code password} is required when the PEM is encrypted
     * and rejected when it is not. Null or an empty array does not decrypt a key.
     */
    public static PrivateKey read(String pem, char[] password) {
        return read(pem, password, true);
    }

    /** Reads one private key from a UTF-8 PEM file. Same password rules as {@link #read(String, char[])}. */
    public static PrivateKey read(Path path, char[] password) {
        return PemFiles.parse(path, pem -> read(pem, password));
    }

    /**
     * Writes one unencrypted PKCS#8 private key. A key with no encoding, such as a hardware key,
     * is rejected.
     */
    public static String write(PrivateKey privateKey) {
        if (privateKey == null) {
            throw new IllegalArgumentException("private key is required");
        }
        byte[] encoded = privateKey.getEncoded();
        if (encoded == null || encoded.length == 0) {
            throw new IllegalArgumentException(
                    "Private key did not provide a PKCS#8 encoding. A hardware key cannot be written as PEM.");
        }
        String format = privateKey.getFormat();
        if (format != null && !"PKCS#8".equalsIgnoreCase(format)) {
            throw new IllegalArgumentException(
                    "Private key encoding is " + format + ", not PKCS#8. PrivateKeys.write writes BEGIN PRIVATE KEY.");
        }
        try {
            PrivateKeyInfo.getInstance(encoded);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Private key encoding is not PKCS#8.", e);
        }
        return PemSyntax.encode("PRIVATE KEY", encoded);
    }

    /**
     * Writes one unencrypted PKCS#8 private key. Fails if {@code path} exists or is a symbolic link.
     * On POSIX the file mode is {@code 0600}. The PEM is not encrypted.
     */
    public static void write(PrivateKey privateKey, Path path) {
        PemFiles.write(path, write(privateKey), true);
    }

    private static PrivateKey read(String pem, char[] password, boolean passwordSupplied) {
        String text = PemSyntax.text(pem, "private key");
        List<String> labels = PemSyntax.labels(text);
        if (labels.isEmpty()) {
            throw new IllegalArgumentException("PEM has no BEGIN line. Expected a single private key.");
        }
        if (labels.size() > 1) {
            throw new IllegalArgumentException(
                    "PEM contains more than one object. PrivateKeys.read reads a single private key.");
        }
        String label = labels.getFirst();
        if (PemSyntax.OPENSSH_PRIVATE_KEY.equals(label)) {
            throw new IllegalArgumentException(
                    "OpenSSH private keys are not supported. Convert the key to PKCS#8 (BEGIN PRIVATE KEY).");
        }
        if (!PRIVATE_KEY_LABELS.contains(label)) {
            throw PemSyntax.wrongType(label, "a private key");
        }
        List<Object> objects = PemSyntax.parse(text, "private key");
        if (objects.size() != 1) {
            throw new IllegalArgumentException("Failed to parse private key PEM");
        }
        return switch (objects.getFirst()) {
            case PrivateKeyInfo info -> unencrypted(passwordSupplied, toPrivateKey(info));
            case PEMKeyPair pair -> unencrypted(passwordSupplied, toPrivateKey(pair));
            case PKCS8EncryptedPrivateKeyInfo encrypted -> decrypt(encrypted, password);
            case PEMEncryptedKeyPair encrypted -> decrypt(encrypted, password);
            default -> throw new IllegalArgumentException(
                    "PEM is labelled " + label + " but did not contain a private key.");
        };
    }

    private static PrivateKey unencrypted(boolean passwordSupplied, PrivateKey key) {
        if (passwordSupplied) {
            throw new IllegalArgumentException("PEM private key is not encrypted. Do not pass a password.");
        }
        return key;
    }

    private static PrivateKey decrypt(PKCS8EncryptedPrivateKeyInfo encrypted, char[] password) {
        char[] usable = requirePassword(password);
        try {
            InputDecryptorProvider decryptor = new JcePKCSPBEInputDecryptorProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(usable);
            return toPrivateKey(encrypted.decryptPrivateKeyInfo(decryptor));
        } catch (PKCSException e) {
            throw wrongPassword(e);
        }
    }

    private static PrivateKey decrypt(PEMEncryptedKeyPair encrypted, char[] password) {
        char[] usable = requirePassword(password);
        try {
            PEMKeyPair pair = encrypted.decryptKeyPair(new JcePEMDecryptorProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(usable));
            return toPrivateKey(pair);
        } catch (IOException e) {
            throw wrongPassword(e);
        }
    }

    private static char[] requirePassword(char[] password) {
        if (password == null) {
            throw new IllegalArgumentException(
                    "PEM private key is encrypted. Pass a password to PrivateKeys.read.");
        }
        if (password.length == 0) {
            throw new IllegalArgumentException("PEM private key is encrypted. The password is empty.");
        }
        return password;
    }

    private static IllegalArgumentException wrongPassword(Exception cause) {
        return new IllegalArgumentException(
                "Failed to decrypt the private key. The password may be wrong.", cause);
    }

    private static PrivateKey toPrivateKey(PrivateKeyInfo keyInfo) {
        try {
            return converter().getPrivateKey(keyInfo);
        } catch (PEMException e) {
            throw new IllegalArgumentException("Failed to read private key PEM", e);
        }
    }

    private static PrivateKey toPrivateKey(PEMKeyPair pair) {
        try {
            return converter().getKeyPair(pair).getPrivate();
        } catch (PEMException e) {
            throw new IllegalArgumentException("Failed to read private key PEM", e);
        }
    }

    private static JcaPEMKeyConverter converter() {
        return new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
    }
}
