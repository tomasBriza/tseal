# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Project Texas is a Java PKI library wrapping Bouncy Castle to simplify certificate issuance, signing, and verification. The API is fluent, type-safe, and hard-to-misuse by design, with safe defaults and prebuilt policies for common cases. Bouncy Castle is the only intended external dependency.

## Commands

```bash
JAVA_HOME=/home/tomas-briza/.jdks/temurin-25.0.3 ./gradlew build   # compile + test (all modules)
JAVA_HOME=/home/tomas-briza/.jdks/temurin-25.0.3 ./gradlew test    # tests only
JAVA_HOME=/home/tomas-briza/.jdks/temurin-25.0.3 ./gradlew :tseal:test
JAVA_HOME=/home/tomas-briza/.jdks/temurin-25.0.3 ./gradlew :tseal-policy-json:test
JAVA_HOME=/home/tomas-briza/.jdks/temurin-25.0.3 ./gradlew :tseal:test --tests "com.tbr.pki.tseal.csr.CsrBuilderTest"
JAVA_HOME=/home/tomas-briza/.jdks/temurin-25.0.3 ./gradlew publishToMavenLocal
```

## Technical Setup

- **Language**: Java 25 (Temurin-25 at `~/.jdks/temurin-25.0.3`)
- **Build system**: Gradle 9.3.0 (wrapper at `./gradlew`)
- **Root package**: `com.tbr.pki.tseal`
- **Modules**: `:tseal` (core, Bouncy Castle only) and `:tseal-policy-json` (Jackson, implementation-only)
- **Dependencies**: core is `bcprov-jdk18on` and `bcpkix-jdk18on`. JSON is a separate artifact.

## Architecture

Six components, delivered across three phases. CSR builder (`com.tbr.pki.tseal.csr`) and
issuance policy (`com.tbr.pki.tseal.policy`) are implemented. See `docs/csr/readme.md` and
`docs/policy/readme.md`.

**Phase 1 — Issuance core**

1. **CSR Builder** (implemented) — Fluent DSL for PKCS#10 CSRs. `KeyPairFactory` generates or the caller reuses a key pair. Prebuilt policies: `httpsCsr()`, `clientAuthCsr()`, `signingCsr()`. Full surface via `custom()`. Escape hatch `.custom(Consumer<RawCsr>)` on every builder. All builders write into a package-private `CsrAccumulator`; `CsrEngine` is the only Bouncy Castle path.

2. **Certificate Policy** (implemented, `com.tbr.pki.tseal.policy`) — `IssuancePolicy` describes how a CSR becomes a certificate. Per-attribute `FieldRule` (identity) and `ValidityRule` (lifetime): from CSR, caller, or default; `exactly` / `forbidden`; whitelist / regex; validity `min` / `max` reject rather than clamp. Typed `.crl(url)` / `.ocsp(url)` / `.caIssuers(url)`. Prebuilt `httpsPolicy()` / `clientAuthPolicy()` / `signingPolicy()`. Independently useful via `check(csr)`. Snapshot/codec SPI for serialization; JSON is `:tseal-policy-json`. Not the X.509 CertificatePolicies extension.

3. **Certificate Signing** — Accepts a CSR (file or string) plus a `CertificatePolicy`. Delegates signing to a pluggable PKCS provider interface (in-memory key or PKCS#11 / HSM). Returns the signed certificate.

**Phase 2 — Validation**

4. **Certificate Validation** — Policy-driven validator. Covers chain building, expiry, and use-case-specific checks. Same three prebuilt policies as above.

**Phase 3 — Revocation**

5. **CRL** — Generates and manages Certificate Revocation Lists via a builder DSL.

6. **OCSP** — Responder and client for revocation status checks, built on the signing/validation tooling.

## Design Principles

- Builder pattern is the primary API surface. Policy customization is a curated builder plus a `RawCsr` escape hatch, not a decorator.
- The PKCS provider for signing is an interface — signing is always delegated, never hardwired.
- Attribute validation in policies uses whitelist or regex rules declared on the policy, not ad-hoc checks in signing code.
- Each phase is independently useful and builds on the previous one.
