# CSR builder

A fluent builder for PKCS#10 Certificate Signing Requests, built on top of Bouncy Castle.

Package: `com.tbr.pki.tseal.csr`

The API has **three levels of input**: a trivial preset for people who don't deal with PKI,
full customization for those who know exactly what they want, and an escape hatch for
everything else (Microsoft enrollment, eIDAS, SCEP).

This document describes the **implemented** API, not a future design.

---

## Contents

- [Design goals](#design-goals)
- [Architecture](#architecture)
- [Public API](#public-api)
    - [Policy builders](#policy-builders)
    - [Generating a key pair](#generating-a-key-pair)
    - [Split keys and HSM signing](#split-keys-and-hsm-signing)
    - [Full customization](#full-customization)
    - [Escape hatch](#escape-hatch)
- [Requested validity](#requested-validity)
- [Key design decisions](#key-design-decisions)
- [Out of scope](#out-of-scope)
- [Resolved decisions](#resolved-decisions)

---

## Design goals

1. **Easy things easy.** A TLS server CSR should be three lines, with no ASN.1 knowledge
   required.
2. **Hard things possible.** Anything PKCS#10 permits must be expressible through the
   library — no fork, no reaching into internal classes.
3. **One engine, one signing path.** All Bouncy Castle and signing logic live in a single
   place. Policy builders are thin presets on top of it, not parallel implementations.
4. **Correct by default.** The library guards against footguns a CA will actually reject:
   empty SAN on TLS (compile time), a hand-picked signature algorithm (derived from the
   public key), country encoded as PrintableString.
5. **No silent magic.** The public key is always supplied explicitly (never derived from the
   private key). The signature algorithm is derived from the public key, but is always
   overridable.

---

## Architecture

Three layers, one-directional dependency top to bottom:

```
┌─────────────────────────────────────────────────────────────┐
│  Public API (fluent builders)                                 │
│                                                               │
│   httpsCsr()   clientAuthCsr()   signingCsr()   custom()      │
│        │              │               │            │          │
│        └──────────────┴───────────────┴────────────┘          │
│                          │ write into                         │
└──────────────────────────┼────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  CsrAccumulator  (package-private, mutable)                   │
│  subject · SAN · ExtensionsGenerator · other attributes ·     │
│  signature / ContentSigner override · adaptive KeyUsage flag  │
└──────────────────────────┼────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  CsrEngine  (package-private)                                 │
│  CsrAccumulator + PublicKey + (PrivateKey | ContentSigner)    │
│                            → CsrResult                        │
│  • finalize extensions   • signature alg derivation           │
│  • single extensionRequest   • signing (proof-of-possession)  │
│  • PEM output                                                 │
│              ── all Bouncy Castle lives here ──               │
└─────────────────────────────────────────────────────────────┘
```

- **Engine** has no fluent surface. It takes the accumulator plus keys (or an explicit
  `ContentSigner`) and returns a `CsrResult`. This is where all extensions are wrapped into a
  **single** `extensionRequest` attribute (the most common CSR bug; the single write path
  makes it structurally unlikely).
- **Accumulator** is the mutable collection point. All builders only write into it, so there
  is no second path into the engine. There is no separate immutable spec object.
- **Policy builder = preset + narrowed surface.** On construction it writes KU / EKU /
  BasicConstraints into the accumulator and exposes only the relevant methods.

Public types: `CsrBuilder`, `CsrResult`, `KeyPairFactory`, `KeyAlgorithm`, `Oids`,
`HttpsStart`, `HttpsBuildable`, `ClientAuthBuilder`, `SigningCertBuilder`,
`CustomCsrBuilder`, `SubjectBuilder`, `SanBuilder`, `RawCsr`.

Package-private: `CsrAccumulator`, `CsrEngine`, `HttpsPolicyBuilder`, `RawCsrImpl`.

---

## Public API

Factory:

```java
CsrBuilder.httpsCsr()       // → HttpsStart
CsrBuilder.clientAuthCsr()  // → ClientAuthBuilder
CsrBuilder.signingCsr()     // → SigningCertBuilder
CsrBuilder.custom()         // → CustomCsrBuilder
```

Every `build(...)` returns:

```java
public record CsrResult(PKCS10CertificationRequest request, String pem) {}
```

```java
result.pem();     // PEM-encoded CSR string
result.request(); // PKCS10CertificationRequest (Bouncy Castle)
```

### Policy builders

Prebuilt policies set KeyUsage / ExtendedKeyUsage / BasicConstraints themselves. The user
supplies identity.

**TLS server** — SAN is mandatory (an empty SAN is an invalid cert), so it is enforced at
compile time (see [type-state](#compile-time-required-parameters)). Curated methods:
`commonName`, `dns`, `ip`, `validity`, `custom`.

```java
CsrResult result = CsrBuilder.httpsCsr()
        .commonName("some server")
        .dns("someserver.com")     // unlocks build()
        .build(keyPair);
```

`ip(...)` also unlocks `build()`. `custom(...)` on `HttpsStart` does **not** — even if the
callback adds a SAN extension, `build()` stays hidden until `dns()` or `ip()` is called.

**Client authentication** — CN-only is legitimate, no type-state. Curated methods:
`commonName`, `organization`, `validity`, `custom`. There is no compile-time or runtime
check that a subject is present.

```java
CsrResult result = CsrBuilder.clientAuthCsr()
        .commonName("client-app")
        .build(keyPair);
```

**Signing certificate (intermediate CA).** Curated methods: `commonName`, `organization`,
`validity`, `custom`. Same as client auth: no required-field check.

```java
CsrResult result = CsrBuilder.signingCsr()
        .commonName("Intermediate CA")
        .organization("Acme Corp")
        .build(keyPair);
```

| Policy            | KeyUsage                                                         | EKU        | BasicConstraints | SAN required |
|-------------------|------------------------------------------------------------------|------------|------------------|--------------|
| `httpsCsr()`      | digitalSignature + keyEncipherment (RSA) / digitalSignature (else) | serverAuth | CA=false         | yes (type-state) |
| `clientAuthCsr()` | digitalSignature                                                 | clientAuth | CA=false         | no           |
| `signingCsr()`    | keyCertSign, cRLSign                                             | —          | CA=true          | no           |

`httpsCsr()` sets an `adaptiveKeyUsage` flag on the accumulator. At build time the engine
writes KeyUsage from the **public key type**: RSA gets `digitalSignature | keyEncipherment`
(TLS 1.2 key transport); every other key type (EC, Ed25519, Ed448) gets `digitalSignature`
only. Client-auth and signing policies write a fixed KeyUsage when the builder is constructed.

### Generating a key pair

`KeyPairFactory` is separate from the builder. It returns a standard `java.security.KeyPair`,
which is passed to any builder:

```java
KeyPair keyPair = KeyPairFactory.generate(KeyAlgorithm.EC_P256);

CsrResult result = CsrBuilder.httpsCsr()
        .commonName("some server")
        .dns("someserver.com")
        .build(keyPair);          // primary, unambiguous path
```

Supported algorithms:

```java
enum KeyAlgorithm {
    RSA_2048, RSA_3072, RSA_4096,
    EC_P256, EC_P384, EC_P521,
    ED25519, ED448
}
```

Generation uses the Bouncy Castle provider (`BC`). The factory registers that provider on
first use if it is not already present.

### Split keys and HSM signing

There is no `build(PrivateKey)` overload. The request body (`SubjectPublicKeyInfo`) needs the
**public** key, so the engine never derives it from the private key (see
[the rationale](#explicit-keys-no-private-key-derivation)). Every builder exposes three
terminal forms:

```java
build(KeyPair keyPair)                              // canonical
build(PublicKey publicKey, PrivateKey privateKey)   // split / externally held key
build(PublicKey publicKey, ContentSigner signer)    // HSM / explicit signer
```

For an HSM-held key (e.g. a PKCS#11 / Luna slot), where signing happens on the device and the
private key is only a handle, pass a `ContentSigner` backed by the right provider.

This single hook covers HSM signing, RSA-PSS with explicit parameters, and any exotic
algorithm — all without widening the typed API.

Signer resolution in the engine, first match wins:

1. The `ContentSigner` passed to `build(PublicKey, ContentSigner)`
2. A signer set via `RawCsr.contentSigner(...)`
3. `JcaContentSignerBuilder` with `RawCsr.signatureAlgorithm(...)` if set, otherwise the
   algorithm [derived from the public key](#auto-signature-algorithm-derivation)

> **Note.** Paths 1 and 2 skip the engine's signature-algorithm derivation. The signer
> carries its own `AlgorithmIdentifier`. This is a low-level escape hatch: the caller is
> assumed to know what they're doing, and a mismatched signer (e.g. an ECDSA signer for an
> RSA key) will fail at build/verify time rather than being caught up front.

### Full customization

`custom()` exposes nested sub-builders. Inner builders are closed with `and()` (the terminal
`build()` is reserved for the whole CSR — see [naming](#naming-and-vs-build)):

```java
CsrResult result = CsrBuilder.custom()
        .subject()
            .commonName("test")
            .organization("asd")
            .organizationalUnit("Platform")
            .country("CZ")                                   // encoded as PrintableString
            .rdn(BCStyle.L, new DERUTF8String("Prague"))
            .rdn(new ASN1ObjectIdentifier("2.5.4.10"), new DERUTF8String("custom value"))
        .and()
        .san()
            .dns("asd.com")
            .ip("10.0.0.5")
            .email("svc@corp")
            .otherName(MS_UPN_OID, new DERUTF8String("svc@corp"))  // UPN
        .and()
        .keyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment)
        .extendedKeyUsage(KeyPurposeId.id_kp_serverAuth)
        .custom(raw -> raw.addAttribute(SOME_OID, new DERPrintableString("Asd")))
        .build(keyPair);
```

`SubjectBuilder<P>` methods: `commonName`, `organization`, `organizationalUnit`, `country`,
`rdn(ASN1ObjectIdentifier, ASN1Encodable)`. `rdn` takes an ASN.1 value, never a raw
`(String, String)`.

`SanBuilder<P>` methods: `dns`, `ip`, `email`, `otherName(ASN1ObjectIdentifier, ASN1Encodable)`.

Both are generic in the parent type; `and()` returns `P`. They are exposed **only** through
`CsrBuilder.custom()`. Policy builders do not expose them — their value is a curated surface
(`commonName`, `organization`, `dns`, `ip`), and anything exotic goes through
`.custom(raw -> …)`, which is available on every builder.

`CustomCsrBuilder` also has `keyUsage(int bits)` (critical),
`extendedKeyUsage(KeyPurposeId... purposes)` (non-critical), and `validity(Duration)`.
It does not preset BasicConstraints; add that via `RawCsr.addExtension(...)` if needed.

### Escape hatch

Low-level handle for everything the typed methods don't cover — Microsoft enrollment
attributes, eIDAS `qcStatements`, SCEP `challengePassword`, any custom OID. Available on
**every** builder via `.custom(Consumer<RawCsr>)`:

```java
public interface RawCsr {
    RawCsr addAttribute(ASN1ObjectIdentifier oid, ASN1Encodable value);
    RawCsr addExtension(ASN1ObjectIdentifier oid, boolean critical, ASN1Encodable value);
    RawCsr subjectRdn(ASN1ObjectIdentifier oid, ASN1Encodable value);
    RawCsr signatureAlgorithm(String jcaName);        // simple override of the AUTO derivation
    RawCsr contentSigner(ContentSigner signer);       // full control: PSS params, HSM, exotic algs
}
```

Example — MS template + challengePassword for enrollment against AD:

```java
CsrBuilder.clientAuthCsr()
        .commonName("svc-account")
        .custom(raw -> raw
            .addAttribute(MS_CERTIFICATE_TEMPLATE_NAME, new DERBMPString("WebServer"))
            .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword,
                          new DERPrintableString("changeit")))
        .build(keyPair);
```

---

## Key design decisions

### Compile-time required parameters

The type-state builder (methods return different interfaces, so `build()` only appears once
the spec is valid) is used **surgically** — only where a missing field produces a CSR a CA
will actually reject. Expressing "at least one of CN or SAN" in the type system is poor, so
it is not pushed further.

Specifically: **`httpsCsr()` enforces SAN** via a single transition (`dns()` / `ip()` →
unlocks `build()`). `clientAuthCsr()` and `signingCsr()` have a flat surface and do **not**
validate required fields at runtime.

```java
public interface HttpsStart {                 // build() is NOT here
    HttpsStart commonName(String cn);
    HttpsBuildable dns(String dns);            // transitions to buildable
    HttpsBuildable ip(String ip);              // transitions to buildable
    HttpsStart validity(Duration duration);    // does NOT unlock build()
    HttpsStart custom(Consumer<RawCsr> customizer);
}
public interface HttpsBuildable {              // build() IS here
    HttpsBuildable commonName(String cn);
    HttpsBuildable dns(String dns);
    HttpsBuildable ip(String ip);
    HttpsBuildable validity(Duration duration);
    HttpsBuildable custom(Consumer<RawCsr> customizer);
    CsrResult build(KeyPair keyPair);
    CsrResult build(PublicKey publicKey, PrivateKey privateKey);
    CsrResult build(PublicKey publicKey, ContentSigner signer);
}
```

A single impl class (`HttpsPolicyBuilder`) implements **both** interfaces. `httpsCsr()`
returns it typed as `HttpsStart`; `dns()` / `ip()` return `this` typed as `HttpsBuildable`.
One class, two views.

### Typed values instead of `(String, String)`

In PKI, string keys are a footgun. SAN entries are not `(String, String)` but typed
`GeneralName`s (dNSName, iPAddress, rfc822Name, otherName…). Therefore:

- typed methods: `.country("CZ")`, `.dns()`, `.ip()`, `.email()`, `.otherName(oid, value)`
- the raw variant takes `ASN1ObjectIdentifier + ASN1Encodable`, **never** two strings

DN encoding uses `X500NameBuilder(BCStyle.INSTANCE)` on the accumulator. Under that style,
most string RDNs (CN, O, OU, …) are UTF8String. `SubjectBuilder.country(...)` wraps the
value in `DERPrintableString` explicitly. There is no `withNameStyle(...)` hook and no
two-letter country check; a CA that needs a different encoding can pass a fully encoded
value through `rdn(...)` or `RawCsr.subjectRdn(...)`.

### Explicit keys, no private-key derivation

The request body (`SubjectPublicKeyInfo`) needs the **public** key; the private key only
signs. The engine does **not** derive the public key from the private one — the derivation
is per-algorithm, fragile, and useless for an HSM-held key, where the private key is a
device handle and the public key sits alongside it. Terminal methods:

- `build(KeyPair)` — canonical path
- `build(PublicKey, PrivateKey)` — split / externally held key
- `build(PublicKey, ContentSigner)` — HSM signing, RSA-PSS with explicit parameters, or any
  exotic algorithm

A caller who has only a `PrivateKey` wraps it in `new KeyPair(pub, priv)` — one line, and
it's visible what's happening. No `build(PrivateKey)` overload, no silent derivation, no
non-CRT-RSA edge case to surprise anyone.

### Auto signature algorithm derivation

The engine maps by public key type (`PublicKey.getAlgorithm()`), not a hardcoded
`"SHA256withRSA"` for every key:

| Key         | Signature algorithm         |
|-------------|-----------------------------|
| RSA         | SHA256withRSA               |
| EC P-256    | SHA256withECDSA             |
| EC P-384    | SHA384withECDSA             |
| EC P-521    | SHA512withECDSA             |
| other EC    | SHA256withECDSA             |
| Ed25519     | Ed25519 (no hash param)     |
| Ed448       | Ed448                       |

EC curve size is read from `ECPublicKey.getParams().getCurve().getField().getFieldSize()`.
Unsupported algorithms throw `IllegalArgumentException`.

RSA-PSS is **opt-in**, never a policy-level default — its parameters (MGF1, salt length,
trailer) can't be expressed by a plain JCA name string, so it goes through
`RawCsr.contentSigner(...)` or `build(PublicKey, ContentSigner)`. Simple overrides use
`RawCsr.signatureAlgorithm(...)`.

### Naming: `and()` vs `build()`

Nested sub-builders are closed with `and()`, never with `build()`. `build(...)`
is reserved exclusively for terminal creation of the whole CSR, so it's always clear from
reading the code what is being closed.

### Engine finalization

Before signing, `CsrEngine` does these extra writes into the accumulator:

1. If `adaptiveKeyUsage` is set (HTTPS policy), add a critical KeyUsage extension from the
   public key type.
2. If any SAN entries were collected, add a non-critical SAN extension.
3. If `validity(...)` was set, add a non-critical `Oids.REQUESTED_VALIDITY` extension
   (`INTEGER` seconds).

If the extensions generator is still empty after that, **no** `extensionRequest` attribute
is added. Extra attributes from `RawCsr.addAttribute(...)` are always copied onto the CSR.

---

## Requested validity

PKCS#10 has no standard notBefore/notAfter. A CSR can still ask for a lifetime so an
issuance policy can use `ValidityRule.fromCsr()` (see [the policy draft](../policy/readme.md)).

Typed method on every CSR builder, including presets. Does **not** unlock HTTPS `build()`
(SAN still does). Omitted means the CSR does not request a lifetime.

```java
CsrResult result = CsrBuilder.httpsCsr()
        .commonName("app")
        .dns("app.acme.com")
        .validity(Duration.ofDays(30))
        .build(keyPair);
```

Encoding: one non-critical `extensionRequest` extension, OID `Oids.REQUESTED_VALIDITY`
(`2.25.` UUID arc), value ASN.1 `INTEGER` (requested lifetime in **seconds**). That is a
duration, not a pair of timestamps — the CA still chooses `notBefore`.

Null, negative, zero, or shorter than one second is rejected at the `validity(...)` call
(`IllegalArgumentException`). A later `validity(...)` call replaces the previous request.
The same extension can also be written via `RawCsr.addExtension`.

---

## Out of scope

This module only creates the request. Still out of scope:

- **Certificate issuance / CA logic.**
- **SCEP/EST/ACME transport.** Delivery is the caller's concern.
- **Key persistence / HSM integration.** `KeyPairFactory` generates in memory; an HSM-held
  key is supported at sign time via `build(PublicKey, ContentSigner)`.
- **Validation against a specific CA policy.** Defaults and type-state prevent a few common
  rejections; the engine does not enforce a given CA's business rules, required subject
  fields, or country format.

---

## Resolved decisions

1. **Key passing.** No `build(PrivateKey)` overload and no public-key derivation. Terminal
   forms are `build(KeyPair)`, `build(PublicKey, PrivateKey)`, and `build(PublicKey, ContentSigner)`.
2. **Sub-builders scope.** `SubjectBuilder` / `SanBuilder` live only on `CsrBuilder.custom()`.
   Policy builders stay curated; exotic needs go through the escape hatch.
3. **RSA-PSS.** Opt-in via `RawCsr.contentSigner(...)` or `build(PublicKey, ContentSigner)`,
   never a policy-level default.
4. **DN encoding.** Hardcoded `BCStyle.INSTANCE`. `country(...)` forces PrintableString.
   No `withNameStyle(...)` and no custom `X500NameStyle`. Different encoding goes through
   `rdn(...)` / `RawCsr.subjectRdn(...)`.
5. **`ContentSigner` branch is unguarded.** It skips algorithm derivation; the caller owns
   correctness, and a mismatch fails at build/verify time. No partial validation that would
   give a false sense of safety.
6. **Required fields.** Only HTTPS SAN is a type-state requirement. Client-auth and signing
   builders do not validate that a subject was set.
