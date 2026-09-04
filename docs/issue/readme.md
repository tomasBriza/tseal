# Certificate issuance

Issues an X.509 certificate from a PKCS#10 CSR and an `IssuancePolicy`. This is Phase 1
step 3. Policy evaluation stays in `policy.engine` — there is no public evaluation DTO
for callers to mutate.

Package: `com.tbr.pki.tseal.issue`

This document describes the **implemented** API, not a future design.

---

## Contents

- [Design goals](#design-goals)
- [Architecture](#architecture)
- [Public API](#public-api)
    - [Type-state](#type-state)
    - [CA-signed leaf](#ca-signed-leaf)
    - [Self-signed CA](#self-signed-ca)
    - [PEM CSR](#pem-csr)
    - [Caller values](#caller-values)
    - [Clock, serial, backdate](#clock-serial-backdate)
    - [HSM / ContentSigner](#hsm--contentsigner)
    - [Customize](#customize)
- [What the engine actually puts on the certificate](#what-the-engine-actually-puts-on-the-certificate)
- [Key design decisions](#key-design-decisions)
- [Out of scope](#out-of-scope)
- [Resolved decisions](#resolved-decisions)

---

## Design goals

1. **Easy things easy.** Sign a TLS leaf with a CA and `httpsPolicy()` in a handful of
   lines. No ASN.1, no serial math, no SKI/AKI.
2. **Hard things possible.** Caller-conditional extensions, HSM signing, a fixed clock
   and serial for tests, self-signed roots.
3. **One engine, one evaluation path.** `IssueEngine` calls the same
   `PolicyEngine.evaluate` that `IssuancePolicy.check` uses. A CSR that fails `check`
   cannot be issued.
4. **Correct by default.** CSR signature (proof of possession) is verified. A non-CA
   issuer is rejected. SKI and AKI are issuer-owned. Duplicate extension OIDs fail
   loudly. Signature algorithm is derived from the signing public key.
5. **No public policy-to-cert bridge.** Callers never see `Evaluation`. The issuer
   consumes it from `policy.engine`.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Public API (type-state builder)                              │
│                                                               │
│   CertificateIssuer.issue()                                   │
│        .csr(...) .policy(...)                                 │
│        .using(ca, key) | .using(ca, signer) | .selfSigned()   │
│        .caller .clock .serial .backdate .customize            │
│        .issue() → IssuedCertificate                           │
│                          │                                    │
└──────────────────────────┼────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  IssueEngine                                                  │
│  1. verify CSR signature                                      │
│  2. PolicyEngine.evaluate (same path as check)                │
│  3. reject non-CA issuer (unless self-signed)                 │
│  4. materialize X.509v3 from the evaluation                   │
│  5. customize (optional)                                      │
│  6. SKI / AKI                                                 │
│  7. sign → IssuedCertificate(cert, pem)                       │
└─────────────────────────────────────────────────────────────┘
```

All issuance types live in `com.tbr.pki.tseal.issue`: `CertificateIssuer`,
`IssueStart`, `IssueWithCsr`, `IssueWithPolicy`, `IssueBuildable`,
`IssuedCertificate`, `RawIssuedCertificate`, `CertificateIssueBuilder`, `IssueEngine`.

`IssuancePolicy`, `CallerValues`, and `PolicyViolationException` are the existing policy
types. Nothing new is added to the JSON module; issuance is core-only.

---

## Public API

### Type-state

Order is enforced at compile time:

```text
issue() → csr(...) → policy(...) → using(...) | selfSigned(...) → issue()
```

Optional knobs (`caller`, `clock`, `serial`, `backdate`, `customize`) are on
`IssueBuildable`, after the issuer is chosen.

### CA-signed leaf

```java
KeyPair caKeys = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
KeyPair leafKeys = KeyPairFactory.generate(KeyAlgorithm.EC_P256);

IssuedCertificate ca = CertificateIssuer.issue()
        .csr(CsrBuilder.signingCsr().commonName("Acme Root").build(caKeys).request())
        .policy(PolicyBuilder.signingPolicy().build())
        .selfSigned(caKeys)
        .issue();

CsrResult csr = CsrBuilder.httpsCsr()
        .commonName("app")
        .dns("app.acme.com")
        .build(leafKeys);

IssuedCertificate leaf = CertificateIssuer.issue()
        .csr(csr.request())
        .policy(PolicyBuilder.httpsPolicy()
                .crl("http://crl.acme.com/acme.crl")
                .build())
        .using(ca.certificate(), caKeys.getPrivate())
        .issue();

leaf.certificate();   // java.security.cert.X509Certificate
leaf.pem();           // PEM-encoded certificate
leaf.certificate().verify(ca.certificate().getPublicKey());
```

`using` overloads:

```java
using(X509Certificate issuerCertificate, PrivateKey issuerKey)
using(X509Certificate issuerCertificate, KeyPair issuerKeyPair)   // public key must match the cert
using(X509Certificate issuerCertificate, ContentSigner signer)    // HSM
```

The issuer certificate must be a CA (`basicConstraints >= 0`). An end-entity cert is
rejected with `IllegalArgumentException`.

### Self-signed CA

```java
IssuedCertificate root = CertificateIssuer.issue()
        .csr(csr.request())
        .policy(PolicyBuilder.signingPolicy().build())
        .selfSigned(caKeys)
        .issue();
```

`selfSigned(KeyPair)` requires the key pair's public key to match the CSR. `selfSigned(PrivateKey)`
is the split-key form when the public key is already in the CSR.

Issuer name is the evaluated subject. SKI and AKI are both derived from the subject
public key.

### PEM CSR

```java
CertificateIssuer.issue()
        .csr(pemString)
        .policy(policy)
        .using(ca.certificate(), caKeys)
        .issue();
```

### Caller values

Same `CallerValues` object that `IssuancePolicy.check` uses. Field rules with
`orCaller()` / `ignoreCsr().orCaller()` read it at issue time:

```java
CertificateIssuer.issue()
        .csr(csr.request())
        .policy(PolicyBuilder.httpsPolicy()
                .organization(ignoreCsr().orCaller().orDefault("Acme"))
                .build())
        .using(ca.certificate(), caKeys.getPrivate())
        .caller(CallerValues.of().organization("West"))
        .issue();
```

`CallerValues.attr(name, value)` is a free-form bag for `customize` (not a FieldRule
source). Read it back with `caller.attr(name)`.

### Clock, serial, backdate

```java
CertificateIssuer.issue()
        .csr(csr.request())
        .policy(policy)
        .using(ca.certificate(), caKeys.getPrivate())
        .clock(Clock.fixed(Instant.parse("2026-01-15T12:00:00Z"), ZoneOffset.UTC))
        .backdate(Duration.ZERO)
        .serial(BigInteger.valueOf(42))
        .issue();
```

| Knob | Default | Notes |
|---|---|---|
| `clock` | `Clock.systemUTC()` | `notBefore = clock.instant() - backdate` |
| `backdate` | 5 minutes | Clock-skew tolerance. Zero is allowed; negative is not. |
| `serial` | 128-bit positive `SecureRandom` | Must be a positive integer if supplied. |

`notAfter` is `notBefore +` the duration the policy resolved (CSR requested validity,
caller, or the policy default). Min/max still **reject**, they do not clamp — that
happens in `PolicyEngine`, before any bytes are signed.

### HSM / ContentSigner

There is no PKCS#11 wrapper. Pass a Bouncy Castle `ContentSigner` backed by the HSM
provider:

```java
ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
        .setProvider("SunPKCS11-Luna")
        .build(hsmPrivateKey);

CertificateIssuer.issue()
        .csr(csr.request())
        .policy(policy)
        .using(ca.certificate(), signer)
        .issue();
```

When a `ContentSigner` is supplied, the engine does not derive a signature algorithm
and does not need the CA private key in process. The issuer certificate is still
required for the issuer name, AKI, and the CA check.

### Customize

Caller-conditional extensions after policy materialization, before SKI/AKI:

```java
var noteOid = new ASN1ObjectIdentifier("1.2.3.4.1");

CertificateIssuer.issue()
        .csr(csr.request())
        .policy(policy)
        .using(ca.certificate(), caKeys.getPrivate())
        .caller(CallerValues.of().attr("note", "west-tenant"))
        .customize((caller, raw) -> {
            if (caller.attr("note") != null) {
                raw.addExtension(noteOid, false, new DERUTF8String(caller.attr("note")));
            }
        })
        .issue();
```

`RawIssuedCertificate.addExtension` fails if the OID is already present (policy CRL/AIA,
KeyUsage, SAN, a previous customize call, …). That is intentional: silent overwrite is
how CAs ship the wrong KeyUsage.

SKI and AKI are added **after** `customize`. Adding those OIDs yourself will fail when
the engine adds its copies.

---

## What the engine actually puts on the certificate

| Field | Source |
|---|---|
| Subject | Policy evaluation (CSR / caller / default / exactly) |
| SAN | Policy evaluation |
| KeyUsage, EKU, BasicConstraints | CA-owned from the policy |
| CRL DP / AIA | Policy `.crl` / `.ocsp` / `.caIssuers` |
| Extra extensions | Policy `RawPolicy.addExtension` and `copyFromCsr` |
| Public key | CSR `SubjectPublicKeyInfo` (after signature verify) |
| Issuer | Issuer certificate subject, or evaluated subject if self-signed |
| Serial | Caller, or 128-bit random |
| notBefore / notAfter | `clock - backdate`, plus evaluated validity |
| SKI / AKI | Always, after customize |
| Signature | CA key or `ContentSigner` |

A policy violation throws `PolicyViolationException` with the same `PolicyViolation`
list and codes as `check`. An invalid CSR signature throws `IllegalArgumentException`.

---

## Key design decisions

### Separate issue package, no public evaluation DTO

`PolicyEngine.evaluate` returns `Evaluation` in `policy.engine`. The issuer is the
intended consumer. A public “here is what the cert would contain” object would freeze a
snapshot that callers then mutate, which is a second issuance API.

`IssuancePolicy.check` remains independently useful: reject a CSR before a CA key is
available.

### Customize, not a policy-time lambda on every extension

Field rules already source identity and validity. KU / EKU / BC stay CA-owned. For
“if this tenant, add this extension,” `customize` sees `CallerValues` at issue time.
That is a Java lambda, not JSON. Persistable extra extensions still go on the policy
(`RawPolicy.addExtension` or JSON `extraExtensions`).

### Duplicate OIDs fail

Bouncy Castle already rejects a second `addExtension` for the same OID. The issuer
does not catch and overwrite. Policy and customize must not fight over CRL DP, AIA,
or KeyUsage.

### Proof of possession is the issuer’s job

`check` does not verify the CSR signature. Issuance does. A CSR whose signature does
not match the embedded public key never becomes a certificate.

### Default 5-minute backdate

Verifiers with a slow clock would otherwise reject a just-issued cert. The default is
a signer concern, not a policy field. Tests that need exact `notBefore` pass
`backdate(Duration.ZERO)`.

### Signature algorithm from the **signing** key

A self-signed cert is signed with the subject key; a CA-signed cert is signed with the
issuer key. The algorithm is derived from that public key, with the same mapping as
the CSR builder (`SHA256withECDSA` for P-256, `Ed25519`, …). An explicit
`ContentSigner` wins.

---

## Out of scope

- **PKCS#11 / HSM wrapper.** `ContentSigner` is the hook. Slot login, PIN, and
  provider config stay with the caller.
- **Sourcing CRL / AIA from FieldRules.** Typed `.crl(url)` on the policy, or
  `customize` / overlay. Not `fromCsr()` on distribution points in this step.
- **Certificate chain / PEM bundle.** `IssuedCertificate` is one cert. The caller
  concatenates intermediates if a server needs them.
- **X.509 CertificatePolicies, name constraints, policy mappings as typed methods.**
  Escape hatch (`customize` or `RawPolicy`).
- **Phase 2 validation.** Issuing a cert does not validate a chain.
- **CRL and OCSP generation.** Phase 3.

---

## Resolved decisions

1. **Entry point.** `CertificateIssuer.issue()` type-state builder, not
   `CertificateSigner.sign(csr, policy, provider)`.
2. **Package.** `com.tbr.pki.tseal.issue`. Policy evaluation stays in `policy.engine`.
3. **Return type.** `IssuedCertificate(X509Certificate, String pem)`.
4. **Signing hooks.** In-memory `PrivateKey` / `KeyPair`, or `ContentSigner`. No
   PKCS-provider interface beyond that.
5. **Self-signed.** First-class `.selfSigned(...)` for roots / test CAs.
6. **Non-CA issuer.** Rejected. `signingPolicy()` produces `CA=true`.
7. **Customize.** `BiConsumer<CallerValues, RawIssuedCertificate>` after policy
   extensions, before SKI/AKI.
8. **Backdate default.** 5 minutes.
9. **Serial.** 128-bit `SecureRandom`, high bit cleared so the value stays positive.
)
