# Issuance policy

Rules for turning a CSR into certificate fields. No key, no signature. Signing is [issue/readme.md](../issue/readme.md).

Packages: `io.github.tomasbriza.tseal.policy`, `.builder`, `.restriction`, `.snapshot`, `.engine`.

Builders fill a `PolicyAccumulator`. `build()` freezes an immutable `IssuancePolicy`. `check` runs `PolicyEngine` and returns `Evaluation`. The name is not `CertificatePolicy`: that collides with the X.509 CertificatePolicies extension, which goes through `RawPolicy` if needed.

Factories: `httpsPolicy()`, `clientAuthPolicy()`, `signingPolicy()`, `custom()` (`CustomPolicyStart`; `validity(...)` unlocks `build()`).

## Presets

Presets set KU, EKU, BasicConstraints, and a default validity rule. They are immediately buildable.

| Policy               | KeyUsage                       | EKU        | BasicConstraints             | SAN                       | Default lifetime |
|----------------------|--------------------------------|------------|------------------------------|---------------------------|------------------|
| `httpsPolicy()`      | adaptive, same as `httpsCsr()` | serverAuth | CA=false, critical           | dns+ip from CSR, ≥1       | 90 days          |
| `clientAuthPolicy()` | digitalSignature               | clientAuth | CA=false, critical           | dns+ip from CSR, optional | 90 days          |
| `signingPolicy()`    | keyCertSign, cRLSign           | —          | CA=true, pathLen=0, critical | forbidden                 | 1825 days        |

Default validity on all three: `ValidityRule.fromCsr().optional().orCaller().orDefault(preset)`. No min/max until set. `.validity(Duration)` replaces the rule with `exactly`. `.validity(ValidityRule)` replaces the whole rule.

`pathLen(0)` means the CA may issue end-entity certs only. `.pathLen(n)` or `.unboundedPathLen()` override. A root that signs intermediates needs `pathLen(1)` or unbounded. See [issue/readme.md](../issue/readme.md#leaf).

HTTPS curated methods: `commonName`, `organization`, `country`, `dns`, `ip`, `crl`, `ocsp`, `caIssuers`, `validity`, `custom`. Client-auth adds the same. Signing uses `pathLen` instead of `dns` / `ip`. `httpsPolicy().build()` already accepts `CsrBuilder.httpsCsr()` output.

## CRL, OCSP, caIssuers

Typed URI methods on every builder, including presets. Not `FieldRule`s. Not read from the CSR.

`crl(uri)` writes `cRLDistributionPoints`, one `DistributionPoint` fullName URI per call. `ocsp(uri)` writes `authorityInfoAccess` `id-ad-ocsp`. `caIssuers(uri)` writes `id-ad-caIssuers` on the same extension.

Repeatable. Null or blank throws `IllegalArgumentException` at the call. Omitted means the extension is absent. Both extensions are non-critical. AIA is omitted when neither OCSP nor caIssuers is set. A CSR that requests CRLDP or AIA fails closed unless `RawPolicy.ignoreCsrExtension`. Scheme is not checked. Reasons, cRLIssuer, and partitioned CRLs are `RawPolicy.addExtension`.

## Field rules

Factories on `Rules`: `fromCsr()`, `exactly(String)`, `forbidden()`, `ignoreCsr()`. Chainable: `optional()`, `orCaller()`, `orDefault(String)`, `matching(regex)`, `oneOf(...)`, `maxLength(int)`, `restrict(RestrictionRule)` or `restrict("typeName")`, `minEntries(int)`, `maxEntries(int)`. Subject default max is 1. SAN default max is unlimited.

Precedence is fixed. Call order does not change it: **CSR → caller → default**.

| Rule                                    | CSR value present     | CSR value absent       | On the cert             |
|-----------------------------------------|-----------------------|------------------------|-------------------------|
| `fromCsr()`                             | must pass constraints | violation              | CSR value               |
| `fromCsr().optional()`                  | must pass constraints | ok, omitted            | CSR value or nothing    |
| `fromCsr().orCaller()`                  | must pass constraints | caller, else violation | CSR or caller           |
| `fromCsr().orDefault("x")`              | must pass constraints | `"x"`                  | CSR or default          |
| `fromCsr().orCaller().orDefault("x")`   | must pass constraints | caller, else `"x"`     | CSR, caller, or default |
| `exactly("x")`                          | ignored               | —                      | `"x"`                   |
| `ignoreCsr().orCaller().orDefault("x")` | ignored               | caller, else `"x"`     | caller or default       |
| `forbidden()`                           | violation             | ok                     | omitted                 |

Constraints apply to the winning value and to a CSR value that will not be used. An illegal CSR value does not fall through.

SAN `dns` / `ip` / `email` are lists. `fromCsr()` copies every entry of that type. `orCaller()` unions caller entries with CSR entries; the default applies only when the union is empty. `exactly` writes one name and ignores the others of that type. `minEntries` / `maxEntries` run after the union.

`country(...)` is PrintableString. Unless `matching` or `oneOf` is already set, the policy also requires `[A-Z]{2}`.

## Restrictions

Built-ins `regex`, `oneOf`, `maxLength`, `country` need no registration. Other checks are in-process. No ServiceLoader.

`RestrictionRules.builtin().bind(name, rule)`, `bind(name, Predicate)`, or `bind(name, Predicate, code, message)`. Use the name with `restrict("name")`. `Allow` and `Reject` are `RestrictionOutcome`. Anonymous `restrict(predicate)` works in memory and does not snapshot. A named bind does, and the JSON type string is that name.

## Validity

`ValidityRule` is separate from `FieldRule` so the static factories do not clash. Same precedence: CSR → caller → default. `min` / `max` are inclusive. Out of range is a violation. The engine does not clamp.

`fromCsr()` reads `Oids.REQUESTED_VALIDITY` (ASN.1 INTEGER seconds). See [csr/readme.md](../csr/readme.md#requested-validity). The policy always owns that OID, including when the rule is `exactly` (the extension is ignored, not an unknown-extension violation). Absolute dates are chosen by the issuer: `notBefore = clock - backdate`, `notAfter = notBefore + duration`.

`validity(ValidityRule)` replaces the rule. `validity(Duration)` is `exactly`.

| Rule                     | Requested lifetime present | Absent                            | On the cert       |
|--------------------------|----------------------------|-----------------------------------|-------------------|
| `fromCsr()`              | must pass min/max          | violation                         | CSR duration      |
| `fromCsr().orCaller()`   | must pass min/max          | caller, else violation            | CSR or caller     |
| `fromCsr().orDefault(d)` | must pass min/max          | `d`                               | CSR or default    |
| `exactly(d)`             | ignored                    | —                                 | `d`               |
| `forbidden()`            | violation                  | needs `orCaller()` or `orDefault` | caller or default |

`forbidden()` without `orCaller()` or `orDefault` throws at build: a certificate cannot omit notAfter. Also at the builder, not at `check`: null / zero / negative duration, `min > max`.

`custom()` has no default. `validity(Duration | ValidityRule)` is the type-state that unlocks `build()`.

## `check`

Overloads: `check(PKCS10CertificationRequest)`, `check(PKCS10CertificationRequest, CallerValues)`, `check(String pem)`, `check(String pem, CallerValues)`. `check(csr)` is `check(csr, CallerValues.empty())`. `orCaller()` with no caller value is the same as not calling `orCaller()`. All violations are collected.

`Evaluation.Ok(subject, san, validity, keyUsageBits, extensions)`. `Evaluation.Violations(violations)`. `Ok.keyUsage()` wraps `keyUsageBits` in `KeyUsage`, or null. A policy miss does not throw. Blank PEM, a non-CSR PEM, and a null CSR throw `IllegalArgumentException`.

`PolicyViolation(field, message, code)`. `field`: `subject.CN`, `subject.O`, `subject.C`, `san.dNSName`, `san.iPAddress`, `extension.request.<oid>`, `unknown.subject.<oid>`, `validity`. `code` is `ViolationCodes` (`value.regex`, `san.unknown`, …).

`check` does not allocate serial, issuer, SKI, AKI, or a signature, and does not verify the CSR signature.

## `CallerValues`

`empty()` and `of()` are the same start. Setters: `commonName`, `organization`, `organizationalUnit`, `country`, `dns`, `ip`, `email`, `validity(Duration)`. `attr(name, value)` is for `customize` only, not a `FieldRule` source.

## `custom()`

`subject()` / `san()` close with `and()`. `build()` is only the policy. `fromCsr().required()` is `fromCsr()`.

`SubjectRuleBuilder`: `commonName`, `organization`, `organizationalUnit`, `country`, `rdn(oid, FieldRule)`. `SanRuleBuilder`: `dns`, `ip`, `email`, `otherName(oid, FieldRule)`.

Also: `keyUsage(int)` (critical), `extendedKeyUsage(KeyPurposeId...)`, `endEntity()` (CA=false, critical), `ca(int pathLen)` (CA=true, critical), `caUnbounded()`, `crl` / `ocsp` / `caIssuers`, `custom(Consumer<RawPolicy>)`. `validity(Duration)` or `validity(ValidityRule)` unlocks `build()`.

No `keyUsage(fromCsr())`. Copying KU / EKU / BC from the CSR is `RawPolicy.copyExtensionFromCsr`.

## `RawPolicy`

`.custom(Consumer<RawPolicy>)` on every builder. Methods: `addExtension(oid, critical, value)`, `copyExtensionFromCsr(oid, required)`, `ignoreCsrExtension(oid)`, `allowSubjectRdn(oid, rule)`, `allowSanType(generalNameTag, rule)`.

`addExtension` is for name constraints, CertificatePolicies, partitioned CRLDP. Do not use it for the typed CRL/OCSP/caIssuers URIs. `copyExtensionFromCsr` is opt-in. `ignoreCsrExtension` skips the unknown-extension violation. `allowSubjectRdn` / `allowSanType` widen a preset without `custom()`.

## What evaluation copies

| From the CSR, if the rule says so | subject RDNs on the allow-list, SAN on the allow-list, requested lifetime, subject public key |
| Never copied; CSR copy is not a violation | KU, EKU, BasicConstraints. Presets rewrite them. |
| Fail closed | subject RDN not in the policy; SAN type not in the policy; `extensionRequest` OID the policy does not own, copy, or ignore |
| Ignored, not a violation | PKCS#9 and Microsoft enrollment attributes (`challengePassword`, template name) |
| CA-owned on the policy | KU, EKU, BC, CRL, OCSP, caIssuers |
| Not on the policy | issuer, serial, SKI, AKI, signature algorithm, absolute dates |

`CsrBuilder.httpsCsr().commonName(...).dns(...).build(kp)` passes `httpsPolicy()`: CN optional, dns required, KU/EKU/BC rewritten. An email SAN fails until `allowSanType(GeneralName.rfc822Name, fromCsr().optional())`.

Snapshot and JSON: [serde.md](serde.md). `IssuancePolicy.snapshot()` / `PolicySnapshot.toPolicy()` need no Jackson.
