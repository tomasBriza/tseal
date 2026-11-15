# PEM

Three types in `io.github.tomasbriza.tseal.pem`. String and `Path`.

```java
X509Certificate leaf = Certificates.read(Path.of("leaf.pem"));
List<X509Certificate> chain = Certificates.readChain(Path.of("fullchain.pem"));
PublicKey publicKey = PublicKeys.read(Path.of("app.pub"));
PrivateKey privateKey = PrivateKeys.read(Path.of("app.key"));
PrivateKey encrypted = PrivateKeys.read(Path.of("app.key"), password);

Certificates.write(leaf, Path.of("leaf.pem"));
Certificates.writeChain(List.of(leaf, intermediate, root), Path.of("fullchain.pem"));
PublicKeys.write(publicKey, Path.of("app.pub"));
PrivateKeys.write(privateKey, Path.of("app.key"));
```

| | Reads | Writes |
|---|---|---|
| `Certificates` | one `CERTIFICATE` or `X509 CERTIFICATE` | `CERTIFICATE` |
| `Certificates.readChain` / `writeChain` | one or more certificates, file order | the same order |
| `PublicKeys` | `PUBLIC KEY`, `RSA PUBLIC KEY` | `PUBLIC KEY` |
| `PrivateKeys` | `PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, `RSA PRIVATE KEY`, `EC PRIVATE KEY`, `DSA PRIVATE KEY` | unencrypted PKCS#8 `PRIVATE KEY` |

`readChain` does not check that the certificates chain or are trusted. `Certificates.read` rejects a file that has more than one certificate and names `readChain`.

A file read is UTF-8, up to 1 MiB. A file write fails if the path exists or is a symbolic link. On POSIX a private key file is mode `0600`. A certificate, chain, or public key file is `0644`.

`PrivateKeys.write` does not encrypt. A key with no PKCS#8 encoding, such as a hardware key, is rejected.

## Passwords

`PrivateKeys.read(pem)` rejects an encrypted key. `PrivateKeys.read(pem, password)` takes a `char[]`. The array is not stored.

| PEM | Password | Result |
|---|---|---|
| Encrypted | non-empty | decrypt |
| Encrypted | null or empty | rejected |
| Unencrypted | any call of the password method | rejected |

A wrong password is `IllegalArgumentException`. The message does not include the password or the key.

OpenSSH (`BEGIN OPENSSH PRIVATE KEY`) is rejected. Convert the key to PKCS#8.

## Rejected input

The exception names the PEM that was found. In a chain it also names the object number, starting at 1.

- `Certificates.read` of more than one object, including a chain.
- A chain entry that is not an X.509 certificate.
- An empty chain, or a null certificate in the list.
- Blank text, no `BEGIN` line, or more than 1 MiB.
- A certificate where a key was required, or a key where a certificate was required.
- `TRUSTED CERTIFICATE` and attribute certificates.
- A missing file, a directory, an empty file, or a file that is not UTF-8.

`PublicKeys.read` does not pull the key out of a certificate. Read the certificate and call `getPublicKey()`.
