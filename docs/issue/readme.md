# Certificate issuance

`CertificateIssuer` in `io.github.tomasbriza.tseal.issue`. One CSR plus one `IssuancePolicy` becomes one certificate.

`issue()` returns `IssueResult.Issued(X509Certificate certificate, String pem)` or `IssueResult.Rejected(List<PolicyViolation>)`. `Rejected` is the same violation list as `Evaluation.Violations`. Nothing is signed.

Throws, not a result:
Note: this could change in future and in those case return also Rejected result

| Condition                                      | Exception                  |
|------------------------------------------------|----------------------------|
| CSR signature invalid                          | `IllegalArgumentException` |
| `using` an end-entity (`basicConstraints < 0`) | `IllegalArgumentException` |
| `selfSigned` public key ≠ CSR public key       | `IllegalArgumentException` |
| null CSR, policy, or signer material           | `IllegalArgumentException` |
| negative backdate, non-positive serial         | `IllegalArgumentException` |
| signer creation, cert conversion, PEM          | `IllegalStateException`    |

`check` does not verify the CSR signature. `issue` does, before policy evaluation.

## Call order

`issue()` → `csr(PKCS10 | PEM)` → `policy(...)` → `using(...)` or `selfSigned(...)` → `issue()`.

After the issuer is chosen, `IssueBuildable` has `caller`, `clock`, `serial`, `backdate`, `customize`.

`using(X509Certificate, PrivateKey)`. `using(X509Certificate, KeyPair)` requires the public key to match the certificate. `using(X509Certificate, ContentSigner)`. `selfSigned(KeyPair)`. `selfSigned(PrivateKey)` uses the CSR public key.

`IssueEngine` order: verify CSR signature, `policy.check`, non-CA check (skipped when self-signed), build X.509v3 from `Evaluation.Ok`, `customize`, SKI/AKI, sign.

## Leaf

`selfSigned` is the root only. Issuer name is the evaluated subject. SKI and AKI both come from the subject public key.

An intermediate is `signingPolicy()` plus `using(parent, parentKey)`. `httpsPolicy` / `clientAuthPolicy` are end-entity. `signingPolicy` is CA. `using` does not choose that; the policy does.

`signingPolicy()` defaults to `pathLen(0)` (may issue end-entity certs, not CAs). A root that signs intermediates needs `.pathLen(1)` or `.unboundedPathLen()`. One `issue()` call, one cert. Chain order for stores is `[leaf, …, root]` — [keystore/readme.md](../keystore/readme.md).

## Knobs

| Knob | Default | Rule |
|---|---|---|
| `clock` | `Clock.systemUTC()` | `notBefore = clock.instant() - backdate` |
| `backdate` | 5 minutes | `>= 0`. Not a policy field. |
| `serial` | 128-bit `SecureRandom`, high bit cleared | positive `BigInteger` if set |
| validity | policy result | `notAfter = notBefore + Evaluation.Ok.validity()`. Min/max already rejected in `check`. |

`CallerValues` is the same object as `IssuancePolicy.check`. `attr(name, value)` is only for `customize`, not for `FieldRule`.

`ContentSigner` skips algorithm derivation and does not need the CA private key in process. The issuer certificate is still required (name, AKI, CA check). Algorithm otherwise follows the **signing** public key, same table as [the CSR builder](../csr/readme.md#keys). Self-signed uses the subject key; CA-signed uses the issuer key.

`customize` runs after policy extensions and before SKI/AKI. `RawIssuedCertificate.addExtension` fails if the OID is already present (Bouncy Castle rejects the second `addExtension`). Adding SKI or AKI yourself fails when the engine adds them.

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
