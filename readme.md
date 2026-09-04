# Project tSeal

[![Build](https://github.com/tomasBriza/tseal/actions/workflows/build.yml/badge.svg)](https://github.com/tomasBriza/tseal/actions/workflows/build.yml)


A small Java PKI library — a wrapper for Bouncy Castle — that simplifies certificate issuance, signing, and verification.

The goal is **not** a full-blown PKI product, but a small, easy-to-use, hard-to-misuse tool with minimal dependencies (Bouncy Castle only). It exposes a fluent, type-safe API with safe defaults and prebuilt policies for the common cases, while staying customizable.

**Modules**

| Artifact | Gradle | Contents |
|---|---|---|
| `com.tbr.pki.tseal:tseal` | `:tseal` | CSR builder, issuance policy, certificate issuance (Bouncy Castle only) |
| `com.tbr.pki.tseal:tseal-policy-json` | `:tseal-policy-json` | JSON codec for `IssuancePolicy` (Jackson) |

**Currently implemented:** PKCS#10 CSR builder (`com.tbr.pki.tseal.csr`), issuance policy (`com.tbr.pki.tseal.policy`), and certificate issuance (`com.tbr.pki.tseal.issue`) — TLS server, client auth, and signing-CA presets, plus a full custom DSL and escape hatches.

```java
KeyPair caKeys = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
KeyPair leafKeys = KeyPairFactory.generate(KeyAlgorithm.EC_P256);

IssuedCertificate ca = CertificateIssuer.issue()
        .csr(CsrBuilder.signingCsr().commonName("Example Root").build(caKeys).request())
        .policy(PolicyBuilder.signingPolicy().build())
        .selfSigned(caKeys)
        .issue();

CsrResult csr = CsrBuilder.httpsCsr()
        .commonName("some server")
        .dns("someserver.com")
        .build(leafKeys);

IssuedCertificate leaf = CertificateIssuer.issue()
        .csr(csr.request())
        .policy(PolicyBuilder.httpsPolicy()
                .crl("http://crl.example.com/ca.crl")
                .ocsp("http://ocsp.example.com")
                .build())
        .using(ca.certificate(), caKeys)
        .issue();

leaf.pem();            // PEM-encoded certificate
leaf.certificate();    // java.security.cert.X509Certificate
```

Typical imports: `com.tbr.pki.tseal.key` (`KeyPairFactory`), `com.tbr.pki.tseal.csr`
(`CsrBuilder`), `com.tbr.pki.tseal.policy` (`PolicyBuilder`), `com.tbr.pki.tseal.issue`
(`CertificateIssuer`).

**Use a local snapshot** (this is `0.1.0-SNAPSHOT`, API may still move):

```bash
./gradlew publishToMavenLocal
```

```kotlin
repositories { mavenLocal(); mavenCentral() }
dependencies {
    implementation("com.tbr.pki.tseal:tseal:0.1.0-SNAPSHOT")
    implementation("com.tbr.pki.tseal:tseal-policy-json:0.1.0-SNAPSHOT") // optional
}
```

Requires Java 25.

**Planned:** certificate validation, CRL, OCSP.

- [Motivation and roadmap](docs/motivation.md)
- [CSR builder API](docs/csr/readme.md)
- [Issuance policy API](docs/policy/readme.md)
- [Certificate issuance API](docs/issue/readme.md)
- [Java KeyStore](docs/keystore/readme.md)
- [Policy JSON serialization](docs/policy/serde.md)

This project was built with help from AI — a playground, and a way to take some of the day-to-day PKI pain out of the job.
