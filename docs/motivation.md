# Motivation

Provide a simple PKI library — a wrapper for Bouncy Castle — that simplifies certificate
issuance, signing, and verification.

The goal is **not** a full-blown PKI product, but a small, easy-to-use, hard-to-misuse tool
with minimal dependencies (Bouncy Castle only). It should expose a fluent, type-safe API with
safe defaults and prebuilt policies for the common cases, while staying customizable.

**Status.** CSR builder, issuance policy, and certificate issuance are implemented.
Validation, CRL, and OCSP are planned. See [csr/readme.md](csr/readme.md),
[policy/readme.md](policy/readme.md), and [issue/readme.md](issue/readme.md).

## Components

### CSR builder

A reusable CSR builder with prebuilt policies, built through a fluent Java builder DSL.
This component is implemented (`com.tbr.pki.tseal.csr`).

- Generate a key pair (`KeyPairFactory`) or reuse an existing one.
- Prebuilt policies for common use cases:
    - TLS server (`httpsCsr()`)
    - Client authentication (`clientAuthCsr()`)
    - Signing / intermediate CA (`signingCsr()`)
- Customize without a decorator:
    - Curated methods on each policy builder.
    - Full nested DSL via `CsrBuilder.custom()` (`subject()`, `san()`, …).
    - Escape hatch `.custom(Consumer<RawCsr>)` on every builder for OIDs the typed API
      does not cover.
- One engine path: every builder writes into a shared accumulator; Bouncy Castle lives
  only in `CsrEngine`.

### Certificate signing

A tool that accepts a CSR and returns the signed certificate. Implemented
(`CertificateIssuer` in `com.tbr.pki.tseal.issue`). See [issue/readme.md](issue/readme.md).

- Accept the CSR as a `PKCS10CertificationRequest` or PEM string.
- Accept an `IssuancePolicy` to evaluate the CSR with (same engine as `check`).
- Return `IssuedCertificate` (JCA `X509Certificate` + PEM).
- Sign with an in-memory CA key or a Bouncy Castle `ContentSigner` (PKCS#11 / HSM).
- Self-signed path for roots. Non-CA issuers are rejected.
- `customize` for caller-conditional extensions after policy materialization.

### Certificate policy

A policy describing how a CSR is turned into a certificate. Implemented
(`com.tbr.pki.tseal.policy`). See [policy/readme.md](policy/readme.md).

- Fluent DSL (`PolicyBuilder`), same three levels as CSR: presets, `custom()`, escape hatch.
- Prebuilt policies: `httpsPolicy()`, `clientAuthPolicy()`, `signingPolicy()`.
- Per-attribute sourcing and validation via `FieldRule` (identity) and `ValidityRule`
  (lifetime):
    - from the CSR (required or optional), with whitelist / regex / length, or min/max
      duration
    - from the CSR, then a sign-time caller value, then a default
    - CA-fixed (`exactly`) or `forbidden`
    - validity min/max **reject**, they do not clamp
- Independently useful: `IssuancePolicy.check(csr)` before a signer exists.
- Serialization via `PolicySnapshot` / `PolicyCodec`; JSON in `:tseal-policy-json`
  ([serde.md](policy/serde.md)).
- Typed `.crl(url)` / `.ocsp(url)` / `.caIssuers(url)` on every builder (CA-owned AIA /
  CRLDP; no ASN.1 required).

### Certificate validation (planned)

A tool that validates a certificate against a policy.

- Provide a DSL to build the validation policy.
- Provide prebuilt policies for common use cases:
    - TLS server (SSL) certificate
    - Client authentication certificate
    - Signing certificate
- Basic checks:
    - chain building and validation
    - expiry validation
    - etc.

### CRL (planned)

- A tool to generate and manage Certificate Revocation Lists.
- Provide a DSL to build the CRL.

### OCSP (planned)

- An OCSP responder and client for checking certificate revocation status.
- Build on the existing signing/validation tooling for signing OCSP responses.

## Phases

Each phase is independently useful and builds on the previous one.

### Phase 1 — Issuance core

1. CSR builder — **done**
2. Certificate policy — **done**
3. Certificate signing (incl. PKCS#11 via `ContentSigner`) — **done**

### Phase 2 — Validation

4. Certificate validation (chain, expiry, policy)

### Phase 3 — Revocation

5. CRL
6. OCSP