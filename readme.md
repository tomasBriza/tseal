# Project tSeal

[![Build](https://github.com/tomasBriza/tseal/actions/workflows/build.yml/badge.svg)](https://github.com/tomasBriza/tseal/actions/workflows/build.yml)


A small Java PKI library — a wrapper for Bouncy Castle — that simplifies certificate issuance, signing, and verification.

The goal is **not** a full-blown PKI product, but a small, easy-to-use, hard-to-misuse tool with minimal dependencies (Bouncy Castle only). It exposes a fluent, type-safe API with safe defaults and prebuilt policies for the common cases, while staying customizable.

**Modules**

| Artifact | Gradle | Contents |
|---|---|---|
| `com.tbr.pki.tseal:tseal` | `:tseal` | CSR builder + issuance policy (Bouncy Castle only) |
| `com.tbr.pki.tseal:tseal-policy-json` | `:tseal-policy-json` | JSON codec for `IssuancePolicy` (Jackson) |

**Currently implemented:** PKCS#10 CSR builder (`com.tbr.pki.tseal.csr`) and issuance policy (`com.tbr.pki.tseal.policy`) — TLS server, client auth, and signing-CA presets, plus a full custom DSL and escape hatches.

```java
KeyPair keyPair = KeyPairFactory.generate(KeyAlgorithm.EC_P256);

CsrResult result = CsrBuilder.httpsCsr()
        .commonName("some server")
        .dns("someserver.com")
        .build(keyPair);

result.pem();      // PEM-encoded CSR
result.request();  // Bouncy Castle PKCS10CertificationRequest

IssuancePolicy policy = PolicyBuilder.httpsPolicy()
        .crl("http://crl.example.com/ca.crl")
        .ocsp("http://ocsp.example.com")
        .build();

policy.check(result.request());
```

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

Requires Java 25. Signing certificates is not in this snapshot — CSR + policy `check()` are.

**Planned:** certificate signing, validation, CRL, OCSP.

- [Motivation and roadmap](docs/motivation.md)
- [CSR builder API](docs/csr/readme.md)
- [Issuance policy API](docs/policy/readme.md)
- [Policy JSON serialization](docs/policy/serde.md)