package io.github.tomasbriza.tseal.pem;

import java.io.IOException;
import java.nio.charset.MalformedInputException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;
import java.util.function.Function;

/** File reads and writes shared by the PEM types. */
final class PemFiles {

    private static final Set<PosixFilePermission> OWNER_ONLY = Set.of(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE);
    private static final Set<PosixFilePermission> WORLD_READABLE = Set.of(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.GROUP_READ,
            PosixFilePermission.OTHERS_READ);

    private PemFiles() {}

    static <T> T parse(Path path, Function<String, T> parser) {
        String pem = read(path);
        try {
            return parser.apply(pem);
        } catch (IllegalArgumentException e) {
            throw PemSyntax.at(e, path);
        }
    }

    static String read(Path path) {
        if (path == null) {
            throw new IllegalArgumentException("path is required");
        }
        try {
            if (!Files.exists(path)) {
                throw new IllegalArgumentException("PEM file does not exist: " + path);
            }
            if (Files.isDirectory(path)) {
                throw new IllegalArgumentException("PEM path is a directory: " + path);
            }
            long size = Files.size(path);
            if (size == 0) {
                throw new IllegalArgumentException("PEM file is empty: " + path);
            }
            if (size > PemSyntax.MAX_BYTES) {
                throw new IllegalArgumentException("PEM file is larger than 1 MiB: " + path);
            }
            return Files.readString(path, StandardCharsets.UTF_8);
        } catch (MalformedInputException e) {
            throw new IllegalArgumentException("PEM file is not UTF-8: " + path, e);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read PEM file: " + path, e);
        }
    }

    /** Writes {@code pem}. A private key file is mode {@code 0600} on POSIX; other PEM files are {@code 0644}. */
    static void write(Path path, String pem, boolean privateKey) {
        if (path == null) {
            throw new IllegalArgumentException("path is required");
        }
        Path parent = path.toAbsolutePath().getParent();
        if (parent == null || !Files.exists(parent)) {
            throw new IllegalArgumentException("Directory does not exist: " + parent);
        }
        if (!Files.isDirectory(parent)) {
            throw new IllegalArgumentException("PEM parent is not a directory: " + parent);
        }
        if (Files.isSymbolicLink(path)) {
            throw new IllegalArgumentException("PEM path is a symbolic link: " + path);
        }
        if (Files.exists(path)) {
            if (Files.isDirectory(path)) {
                throw new IllegalArgumentException("PEM path is a directory: " + path);
            }
            throw new IllegalArgumentException("PEM file already exists: " + path);
        }
        boolean posix = FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
        Path temporary;
        try {
            temporary = Files.createTempFile(parent, ".tseal-", ".pem");
        } catch (IOException e) {
            throw new IllegalStateException("Failed to write PEM file: " + path, e);
        }
        try {
            if (posix) {
                Files.setPosixFilePermissions(temporary, privateKey ? OWNER_ONLY : WORLD_READABLE);
            }
            Files.writeString(temporary, pem, StandardCharsets.UTF_8, StandardOpenOption.TRUNCATE_EXISTING);
            try {
                Files.move(temporary, path, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temporary, path);
            }
        } catch (FileAlreadyExistsException e) {
            deleteQuietly(temporary);
            throw new IllegalArgumentException("PEM file already exists: " + path, e);
        } catch (IOException e) {
            deleteQuietly(temporary);
            throw new IllegalStateException("Failed to write PEM file: " + path, e);
        }
        if (posix && privateKey) {
            try {
                Files.setPosixFilePermissions(path, OWNER_ONLY);
            } catch (IOException e) {
                deleteQuietly(path);
                throw new IllegalStateException(
                        "Failed to restrict private key file permissions: " + path, e);
            }
        }
    }

    private static void deleteQuietly(Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (IOException ignored) {
            // The caller reports the original failure.
        }
    }
}
