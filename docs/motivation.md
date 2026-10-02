# Motivation

Bouncy Castle is the crypto engine. tSeal is the issuance API: PKCS#10, an issuance policy, and one certificate. It is not a CA and not a second path-building stack.

Policy is data. `IssuancePolicy.check` does not need a CA key. The same object is what `CertificateIssuer` evaluates. JSON is optional (`:tseal-policy-json`).

## Status

|                 | Package                             | State                                       |
|-----------------|-------------------------------------|---------------------------------------------|
| CSR             | `io.github.tomasbriza.tseal.csr`    | done — [csr/readme.md](csr/readme.md)       |
| Issuance policy | `io.github.tomasbriza.tseal.policy` | done — [policy/readme.md](policy/readme.md) |
| Issue           | `io.github.tomasbriza.tseal.issue`  | done — [issue/readme.md](issue/readme.md)   |
| Validation      | JCA `CertPathValidator` / PKIX      | planned                                     |
| CRL             | —                                   | planned                                     |
| OCSP            | —                                   | planned                                     |

Presets on the implemented pieces: TLS server, client auth, signing CA. Each has `custom()` and a `Raw*` escape hatch. HSM signing is a Bouncy Castle `ContentSigner`, not a PKCS#11 wrapper. Keystore I/O stays on JCA — [keystore/readme.md](keystore/readme.md).

Note: Validation, when built, should use the JCA PKIX validator. CRL and OCSP come after that.
