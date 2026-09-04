# Java KeyStore

tSeal has no `KeyStore` type. It takes and returns JCA objects (`PrivateKey`,
`PublicKey`, `KeyPair`, `X509Certificate`). `java.security.KeyStore` is how you load
and save those — PKCS#12, JKS, or PKCS#11.

This document describes the **implemented** wiring, not a future helper API.

---

## Load a CA and issue a leaf

```java
KeyStore ks = KeyStore.getInstance("PKCS12");
try (InputStream in = Files.newInputStream(Path.of("ca.p12"))) {
    ks.load(in, storePassword);
}

PrivateKey caKey = (PrivateKey) ks.getKey("ca", keyPassword);
X509Certificate caCert = (X509Certificate) ks.getCertificate("ca");

KeyPair leafKeys = KeyPairFactory.generate(KeyAlgorithm.EC_P256);

CsrResult csr = CsrBuilder.httpsCsr()
        .commonName("app")
        .dns("app.acme.com")
        .build(leafKeys);

IssuedCertificate leaf = CertificateIssuer.issue()
        .csr(csr.request())
        .policy(PolicyBuilder.httpsPolicy().build())
        .using(caCert, caKey)
        .issue();
```

`using(X509Certificate, PrivateKey)` is the keystore-shaped overload. The issuer
certificate must be a CA (`basicConstraints >= 0`).

`using(caCert, new KeyPair(caCert.getPublicKey(), caKey))` also works; the public key
must match the certificate.

---

## CSR from a key already in the store

CSR build never derives the public key from the private key. A keystore entry already
has both:

```java
PrivateKey leafKey = (PrivateKey) ks.getKey("app", keyPassword);
PublicKey leafPub = ks.getCertificate("app").getPublicKey();

CsrResult csr = CsrBuilder.httpsCsr()
        .dns("app.acme.com")
        .build(leafPub, leafKey);
```

`build(new KeyPair(leafPub, leafKey))` is equivalent.

---

## Store the issued certificate

`IssuedCertificate` is one cert, not a chain. Put leaf then CA on the key entry:

```java
Certificate[] chain = { leaf.certificate(), caCert };
ks.setKeyEntry("app", leafKeys.getPrivate(), keyPassword, chain);
try (OutputStream out = Files.newOutputStream(Path.of("app.p12"))) {
    ks.store(out, storePassword);
}
```

That PKCS#12 is what a TLS server / `keytool` expects: alias `app`, private key, leaf,
then issuer.

Three-level chain (root signs an intermediate, intermediate signs the leaf):

```java
IssuedCertificate root = CertificateIssuer.issue()
        .csr(CsrBuilder.signingCsr().commonName("Acme Root").build(rootKeys).request())
        .policy(PolicyBuilder.signingPolicy().unboundedPathLen().build())
        .selfSigned(rootKeys)
        .issue();

IssuedCertificate intermediate = CertificateIssuer.issue()
        .csr(CsrBuilder.signingCsr().commonName("Acme Intermediate").build(intKeys).request())
        .policy(PolicyBuilder.signingPolicy().pathLen(0).build())
        .using(root.certificate(), rootKeys.getPrivate())
        .issue();

IssuedCertificate leaf = CertificateIssuer.issue()
        .csr(CsrBuilder.httpsCsr().dns("app.acme.com").build(leafKeys).request())
        .policy(PolicyBuilder.httpsPolicy().build())
        .using(intermediate.certificate(), intKeys.getPrivate())
        .issue();

Certificate[] chain = { leaf.certificate(), intermediate.certificate(), root.certificate() };
ks.setKeyEntry("app", leafKeys.getPrivate(), keyPassword, chain);
```

`selfSigned` is only the root. Every other cert in the chain, including the issuing CA,
is `using(parentCert, parentKey)` plus the right policy (`signingPolicy` vs `httpsPolicy`).

Self-signed root:

```java
KeyPair caKeys = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
IssuedCertificate ca = CertificateIssuer.issue()
        .csr(CsrBuilder.signingCsr().commonName("Acme Root").build(caKeys).request())
        .policy(PolicyBuilder.signingPolicy().build())
        .selfSigned(caKeys)
        .issue();

ks.setKeyEntry("ca", caKeys.getPrivate(), keyPassword,
        new Certificate[] { ca.certificate() });
```

Intermediates: `getCertificateChain(alias)` on the CA entry if you already stored them;
tSeal does not emit a bundle. Concatenate `[leaf, …intermediates, root]` yourself.

---

## PKCS#11

`KeyStore.getInstance("PKCS11")` still yields a `PrivateKey` (often a handle) and an
`X509Certificate`. Passing that `PrivateKey` to `using(caCert, caKey)` only works if
Bouncy Castle can sign with that provider.

The supported HSM path is an explicit `ContentSigner`. The cert still comes from the
keystore (issuer name, AKI, CA check); signing stays on the token.

```java
ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
        .setProvider("SunPKCS11-Luna")
        .build(caKey);

CertificateIssuer.issue()
        .csr(csr.request())
        .policy(policy)
        .using(caCert, signer)
        .issue();
```

Same split for a CSR: `build(publicKey, signer)`. Slot login, PIN, and provider config
are the caller’s.

See [CSR split keys](../csr/readme.md#split-keys-and-hsm-signing) and
[issuance ContentSigner](../issue/readme.md#hsm--contentsigner).

---

## Notes

| | |
|---|---|
| Format | PKCS#12 is the usual choice. JKS uses the same `KeyStore` API. |
| Alias | `getKey`, `getCertificate`, and `setKeyEntry` share one alias. |
| Passwords | Store password and key password may differ (`PasswordProtection`). |
| Ed25519 | tSeal will issue it; the keystore/provider must be able to store it. |
| No helper | Load/store stay on JCA. tSeal does not wrap `KeyStore`. |
