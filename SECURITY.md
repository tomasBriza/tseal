# Security Policy

This library is a `0.1.0-SNAPSHOT`. There is no supported stable release yet. Report
issues anyway — issuance bugs are security bugs.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/tomasBriza/tseal/security/advisories/new)
on this repository. Do not open a public issue for a key-handling, issuance, or
policy-bypass problem.

Please include:

- tSeal version / git revision
- JDK version
- A minimal CSR / policy / issuer that reproduces the issue

## What this project considers in scope

- A CSR that fails policy still being issued
- An end-entity certificate accepted as issuer
- CSR signature (proof of possession) not verified at issue time
- Policy snapshot / JSON loading a weaker policy than the document describes
- Pathological serial / validity handling that produces a cert the caller did not ask for

## Out of scope (see also the readme)

- Compromise of a caller-held private key or HSM PIN
- Operating a CA (registration, identity proofing, audit, key ceremony)
- Trust after issuance: chain validation, name constraints, revocation (CRL/OCSP) — not implemented
- Issues in Bouncy Castle or the JCA provider you pass in
