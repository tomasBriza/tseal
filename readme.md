# tSeal

[![Build](https://github.com/tomasBriza/tseal/actions/workflows/build.yml/badge.svg)](https://github.com/tomasBriza/tseal/actions/workflows/build.yml)

This project was built with help from AI — a playground, and a way to take some of the day-to-day PKI pain out of the job.

A small Java PKI library wrapping Bouncy Castle. BC is the crypto engine; tSeal is a hard-to-misuse issuance API, not a replacement for calling BC yourself or for running a CA (EJBCA, Boulder, …).

**Policy is data.** An `IssuancePolicy` is a value you can `check(csr)` without a CA key, snapshot, serialize to JSON, and compose with `extends`. Signing consumes that same policy. It is not the X.509 CertificatePolicies extension.

```java
KeyPair caKeys = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
KeyPair leafKeys = KeyPairFactory.generate(KeyAlgorithm.EC_P256);

IssuedCertificate ca = CertificateIssuer.issue()
        .csr(CsrBuilder.signingCsr().commonName("Example Root").build(caKeys).request())
        .policy(PolicyBuilder.signingPolicy().build())
        .selfSigned(caKeys)
        .issue();

IssuancePolicy policy = PolicyBuilder.httpsPolicy()
        .crl("http://crl.example.com/ca.crl")
        .ocsp("http://ocsp.example.com")
        .build();

CsrResult csr = CsrBuilder.httpsCsr()
        .commonName("some server")
        .dns("someserver.com")
        .build(leafKeys);

policy.check(csr.request());   // no CA key required

IssuedCertificate leaf = CertificateIssuer.issue()
        .csr(csr.request())
        .policy(policy)
        .using(ca.certificate(), caKeys)
        .issue();
```

Typical imports: `com.tbr.pki.tseal.key` (`KeyPairFactory`), `com.tbr.pki.tseal.csr`
(`CsrBuilder`), `com.tbr.pki.tseal.policy` (`PolicyBuilder`), `com.tbr.pki.tseal.issue`
(`CertificateIssuer`).

**Currently implemented:** PKCS#10 CSR builder, issuance policy, certificate issuance —
TLS server, client auth, and signing-CA presets, plus a custom DSL and escape hatches.
Java 21. Apache-2.0.

**Planned:** certificate validation (JCA `CertPathValidator` / PKIX), CRL, OCSP.

## What this library does not do

tSeal issues certificates in-process from a CSR and a policy. It is not a CA.

- **No identity proofing, registration, or audit.** Whoever holds the CA key is the CA.
- **No private-key protection.** Keys come from the caller (`KeyPair`, `PrivateKey`,
  `ContentSigner`, or a JCA `KeyStore`). PIN, HSM login, and storage are yours.
- **`check` does not verify CSR proof-of-possession.** Issuance does.
- **No chain validation, name constraints, or revocation.** A just-issued cert is not
  “trusted”; Phase 2 will sit on `CertPathValidator` / PKIX, not a custom path builder.
- **No PEM bundle.** `IssuedCertificate` is one cert. Assemble `[leaf, …, root]` yourself.
- **Policy is not a threat model.** A JSON document does not replace operational CA
  security, CT, or pinning.

See [SECURITY.md](SECURITY.md).

## Modules

| Artifact | Gradle | Contents |
|---|---|---|
| `io.github.tomasbriza:tseal` | `:tseal` | CSR builder, issuance policy, certificate issuance (Bouncy Castle only) |
| `io.github.tomasbriza:tseal-policy-json` | `:tseal-policy-json` | JSON codec for `IssuancePolicy` (Jackson) |

**Use a local snapshot** (this is `0.1.0-SNAPSHOT`, API may still move):

```bash
./gradlew publishToMavenLocal
```

```kotlin
repositories { mavenLocal(); mavenCentral() }
dependencies {
    implementation("io.github.tomasbriza:tseal:0.1.0-SNAPSHOT")
    implementation("io.github.tomasbriza:tseal-policy-json:0.1.0-SNAPSHOT") // optional
}
```

Maven Central is not published yet.

- [Motivation and roadmap](docs/motivation.md)
- [CSR builder API](docs/csr/readme.md)
- [Issuance policy API](docs/policy/readme.md)
- [Certificate issuance API](docs/issue/readme.md)
- [Java KeyStore](docs/keystore/readme.md)
- [Policy JSON serialization](docs/policy/serde.md)
