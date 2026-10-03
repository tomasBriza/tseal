# Certificate issuance

`CertificateIssuer` in `io.github.tomasbriza.tseal.issue`. One CSR plus one `IssuancePolicy` becomes one certificate.

`issue()` returns `IssueResult.Issued(X509Certificate certificate, String pem)` or `IssueResult.Rejected(List<PolicyViolation>)`. Nothing is signed.

`Rejected` is a policy miss (`Evaluation.Violations`, same list) or one of these. `code` is from `ViolationCodes`.

| Condition                                                        | `code`          |
|------------------------------------------------------------------|-----------------|
| CSR signature invalid                                            | `csr.signature` |
| `using` an end-entity (`basicConstraints < 0`)                   | `issuer.notCa`  |
| `selfSigned` or `using(cert, keyPair)` public key does not match | `key.mismatch`  |
| null CSR, policy, or signer material                             | `issue.input`   |
| negative backdate, non-positive serial                           | `issue.input`   |
| signer creation, cert conversion, PEM, key identifiers           | `issue.failed`  |

`check` does not verify the CSR signature. `issue` does, before policy evaluation.

## Call order

`issue()` → `csr(PKCS10 | PEM)` → `policy(...)` → `using(...)` or `selfSigned(...)` → `issue()`.

After the issuer is chosen, `IssueBuildable` has `caller`, `clock`, `serial`, `backdate`, `customize`.

`using(X509Certificate, PrivateKey)`. `using(X509Certificate, KeyPair)`: a public key that does not match the certificate is `Rejected` with `key.mismatch`. `using(X509Certificate, ContentSigner)`. `selfSigned(KeyPair)`: a public key that does not match the CSR is the same code. `selfSigned(PrivateKey)` uses the CSR public key.

`IssueEngine` order: verify CSR signature, `policy.check`, non-CA check (skipped when self-signed), build X.509v3 from `Evaluation.Ok`, `customize`, SKI/AKI, sign.

## Leaf

`selfSigned` is the root only. Issuer name is the evaluated subject. SKI and AKI both come from the subject public key.

An intermediate is `signingPolicy()` plus `using(parent, parentKey)`. `httpsPolicy` / `clientAuthPolicy` are end-entity. `signingPolicy` is CA. `using` does not choose that; the policy does.

`signingPolicy()` defaults to `pathLen(0)` (may issue end-entity certs, not CAs). A root that signs intermediates needs `.pathLen(1)` or `.unboundedPathLen()`. One `issue()` call, one cert. Chain order for stores is `[leaf, …, root]` — [keystore/readme.md](../keystore/readme.md).

## Knobs

| Knob | Default | Rule |
|---|---|---|
| `clock` | `Clock.systemUTC()` | `notBefore = clock.instant() - backdate` |
| `backdate` | 5 minutes | Negative or null is `Rejected`, code `issue.input`. Not a policy field. |
| `serial` | 128-bit `SecureRandom`, high bit cleared | Non-positive is `Rejected`, code `issue.input`. |
| validity | policy result | `notAfter = notBefore + Evaluation.Ok.validity()`. Min/max already rejected in `check`. |

`CallerValues` is the same object as `IssuancePolicy.check`. `attr(name, value)` is only for `customize`, not for `FieldRule`.

`ContentSigner` skips algorithm derivation and does not need the CA private key in process. The issuer certificate is still required (name, AKI, CA check). Algorithm otherwise follows the **signing** public key, same table as [the CSR builder](../csr/readme.md#keys). Self-signed uses the subject key; CA-signed uses the issuer key.

`customize` runs after policy extensions and before SKI/AKI. `RawIssuedCertificate.addExtension` still throws `IllegalArgumentException` when the OID is already present. Adding SKI or AKI yourself fails the same way when the engine adds them.

## Certificate fields

| Field                           | Source                                                        |
|---------------------------------|---------------------------------------------------------------|
| Subject, SAN, lifetime          | `Evaluation.Ok`                                               |
| KeyUsage, EKU, BasicConstraints | policy                                                        |
| CRL DP, AIA                     | policy `.crl` / `.ocsp` / `.caIssuers`                        |
| Other extensions                | `RawPolicy.addExtension`, `copyExtensionFromCsr`, `customize` |
| Public key                      | CSR, after signature verify                                   |
| Issuer                          | issuer cert subject, or evaluated subject if self-signed      |
| Serial                          | caller, or 128-bit random                                     |
| notBefore / notAfter            | clock − backdate, plus evaluated lifetime                     |
| SKI, AKI                        | always, after customize                                       |
| Signature                       | CA key or `ContentSigner`                                     |

Out of scope: PKCS#11 login, PEM bundles, chain validation, CRL/OCSP generation, typed name constraints or X.509 CertificatePolicies (use `customize` or `RawPolicy`).
