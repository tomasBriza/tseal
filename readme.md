# tSeal

[![Build](https://github.com/tomasBriza/tseal/actions/workflows/build.yml/badge.svg)](https://github.com/tomasBriza/tseal/actions/workflows/build.yml)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.tomasbriza/tseal?label=Maven%20Central)](https://central.sonatype.com/artifact/io.github.tomasbriza/tseal)

A small Java PKI library wrapping Bouncy Castle. BC is the crypto engine; tSeal is a hard-to-misuse issuance API, not a replacement for calling BC yourself or for running a CA (EJBCA, Boulder, …).

**Policy is data.** An `IssuancePolicy` is a value you can `check(csr)` without a CA key, snapshot, serialize to JSON, and compose with `extends`. Signing consumes that same policy. It is not the X.509 CertificatePolicies extension. `check` returns `Evaluation.Ok` or `Evaluation.Violations`. `issue()` returns `IssueResult.Issued` or `IssueResult.Rejected`. A bad CSR signature, a non-CA issuer, or a signer failure is `Rejected`.

**Currently implemented:** PKCS#10 CSR builder, issuance policy, certificate issuance —
TLS server, client auth, and signing-CA presets, plus a custom DSL and escape hatches.
Java 21. Apache-2.0.

**Planned:** certificate validation (JCA `CertPathValidator` / PKIX), CRL, OCSP. If required 

## What this library does not do

tSeal issues certificates in-process from a CSR and a policy. It is not a CA.

- **No identity proofing, registration, or audit.** Whoever holds the CA key is the CA.
- **No private-key protection.** Keys come from the caller (`KeyPair`, `PrivateKey`,
  `ContentSigner`, or a JCA `KeyStore`). PIN, HSM login, and storage are yours.
- **`check` does not verify CSR proof-of-possession.** Issuance does.
- **No chain validation, name constraints, or revocation.** A just-issued cert is not
  “trusted”; Phase 2 will sit on `CertPathValidator` / PKIX, not a custom path builder.
- **No PEM bundle.** `IssueResult.Issued` is one cert. Assemble `[leaf, …, root]` yourself.
- **Policy is not a threat model.** A JSON document does not replace operational CA
  security, CT, or pinning.

See [SECURITY.md](SECURITY.md).

## Modules

| Artifact                                 | Gradle               | Contents                                                                |
|------------------------------------------|----------------------|-------------------------------------------------------------------------|
| `io.github.tomasbriza:tseal`             | `:tseal`             | CSR builder, issuance policy, certificate issuance (Bouncy Castle only) |
| `io.github.tomasbriza:tseal-policy-json` | `:tseal-policy-json` | JSON codec for `IssuancePolicy` (Jackson)                               |

Maven Central:

```kotlin
repositories { mavenCentral() }
dependencies {
    implementation("io.github.tomasbriza:tseal:0.1.0")
    implementation("io.github.tomasbriza:tseal-policy-json:0.1.0") // optional
}
```

- [Motivation and roadmap](docs/motivation.md)
- [CSR builder API](docs/csr/readme.md)
- [Issuance policy API](docs/policy/readme.md)
- [Certificate issuance API](docs/issue/readme.md)
- [Java KeyStore](docs/keystore/readme.md)
- [Policy JSON serialization](docs/policy/serde.md)

Boilerplate and first-pass docs are from AI; the issuance model, fail-closed rules, and threat boundary are mine.
