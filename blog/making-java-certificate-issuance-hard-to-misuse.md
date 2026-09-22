# Making Java certificate issuance hard to misuse

Bouncy Castle can do everything. That is also the problem.

A CSR that asks for `CA=true`, a leaf used as an issuer, KeyUsage copied from the request because it was already there — none of these are exotic bugs. They show up when you issue “just one cert” between other work. I wanted an API where those mistakes are loud, and the usual path (TLS server, client auth, a small CA chain) does not require ASN.1.

This is not a CA product. It is a thin, fluent layer on Bouncy Castle: build a CSR, describe how it becomes a certificate, sign it. I used it as a playground — including with AI in the loop — to take some of the day-to-day PKI pain out of the job.

## Three objects

Most issuance I do is the same three steps:

1. A **CSR** — identity and a proof of possession.
2. A **policy** — what the CA will actually put on the cert (and what it will refuse).
3. An **issuer** — a parent key, or self-signed for a root.

The policy is not the X.509 CertificatePolicies extension. It is the issuance profile: subject and SAN rules, validity, KeyUsage, BasicConstraints, CRL/OCSP URLs. `check(csr)` works before a CA key exists. Signing uses the same evaluation; a CSR that fails `check` never becomes a certificate.

Presets cover the three cases I actually issue: `httpsCsr` / `httpsPolicy`, client auth, and signing CA. Everything else is a custom builder or an escape hatch, not a decorator stack.

## The chain is the point

`selfSigned` is only the root. What the cert *is* comes from the policy: `signingPolicy` is a CA, `httpsPolicy` is a leaf. An intermediate is the same `using(parent, parentKey)` path as a leaf.

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
```

A `pathLen(0)` CA may issue end-entity certs, not further CAs. A root that signs intermediates needs `pathLen(1)` or `unboundedPathLen()`. Using a leaf as issuer is rejected.

Each `issue()` returns one certificate. The chain `[leaf, intermediate, root]` is the caller’s to assemble — typically into a PKCS#12.

## What I refused

- Deriving a public key from a private key (CSR body needs the public key explicitly).
- Copying KeyUsage / BasicConstraints from the CSR as a typed API. The CA owns those.
- A public “here is what the cert would contain” object. Evaluation stays behind `check` and `issue`.
- Wrapping `KeyStore`. JCA already loads PKCS#12 / JKS / PKCS#11; this layer takes `PrivateKey` and `X509Certificate`.

HSM signing is a Bouncy Castle `ContentSigner`. No PKCS#11 wrapper.

## Status

Java 21, `0.1.0-SNAPSHOT`, API may still move. No chain validator, CRL, or OCSP yet. That is fine for a first cut: issuance is the part I needed a safer shape for.

Code for this post: [github.com/tomasBriza/tseal](https://github.com/tomasBriza/tseal). Later notes can cover policy rules, JSON snapshots, and KeyStore wiring in more depth.
