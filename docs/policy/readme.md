# Certificate policy

A fluent builder for **issuance policies**: the rules that say how a CSR becomes a
certificate. This is Phase 1 step 2. It does not sign. Issuance (step 3) takes a CSR plus
an `IssuancePolicy` plus a CA key or `ContentSigner` — see [issue/readme.md](../issue/readme.md).

Packages: `com.tbr.pki.tseal.policy` (façade + rules), `.builder`, `.restriction`,
`.snapshot`, `.engine`. Issuance is `com.tbr.pki.tseal.issue`.

The API has **three levels of input**, same shape as the CSR builder: a trivial preset, a
full custom surface, and an escape hatch.

This document describes the **implemented** API, not a future design.

---

## Contents

- [Design goals](#design-goals)
- [Architecture](#architecture)
- [Public API](#public-api)
    - [Policy builders](#policy-builders)
    - [Revocation URLs](#revocation-urls)
    - [Field rules](#field-rules)
    - [Validity](#validity)
    - [Checking a CSR](#checking-a-csr)
    - [Caller values](#caller-values)
    - [Full customization](#full-customization)
    - [Escape hatch](#escape-hatch)
- [What a preset actually puts on the certificate](#what-a-preset-actually-puts-on-the-certificate)
- [Key design decisions](#key-design-decisions)
- [Out of scope](#out-of-scope)
- [Resolved decisions](#resolved-decisions)
- [Serialization](#serialization)

---

## Design goals

1. **Easy things easy.** A TLS issuance policy that accepts our own `httpsCsr()` output
   should be one line, with no ASN.1 knowledge required.
2. **Hard things possible.** Any sourcing rule (CSR / caller / default / CA-fixed /
   forbidden) and any extra extension must be expressible — no fork, no reaching into
   internal classes.
3. **One engine, one evaluation path.** All CSR parsing, rule evaluation, and
   “would this be accepted?” logic live in a single place. Policy builders are thin
   presets on top of it, not parallel implementations.
4. **Correct by default.** The CA is authoritative for KeyUsage, ExtendedKeyUsage, and
   BasicConstraints. Unexpected subject RDNs, SAN types, and requested extensions fail
   closed. A leaf policy cannot emit `CA=true` just because the CSR asked.
5. **No silent magic.** Fallbacks have a fixed precedence that fluent call order cannot
   change. Unknown CSR fields are not quietly dropped. Validity is sourced like any other
   field (CSR → caller → default). Min/max **reject**, they do not clamp. Preset defaults
   are documented.
6. **Independently useful.** A policy can `check` a CSR before a signer exists.

---

## Architecture

Three layers, one-directional dependency top to bottom — the same diagram as CSR, with a
different artifact:

```
┌─────────────────────────────────────────────────────────────┐
│  Public API (fluent builders)                                 │
│                                                               │
│   httpsPolicy()  clientAuthPolicy()  signingPolicy()  custom()│
│        │                │                  │            │     │
│        └────────────────┴──────────────────┴────────────┘     │
│                          │ write into                         │
└──────────────────────────┼────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  PolicyAccumulator  (policy.engine, mutable)                  │
│  subject rules · SAN rules · CA-owned extensions · validity · │
│  CRL / OCSP URIs · extra extensions · allow/ignore lists      │
│                          │ freeze                             │
└──────────────────────────┼────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  IssuancePolicy  (immutable, public)                          │
│                          │                                    │
│              PolicyEngine.check / evaluate                    │
│  CSR + CallerValues + Clock                                   │
│       → violations  |  resolved subject/SAN/extensions/dates  │
│              ── all Bouncy Castle lives here ──               │
└─────────────────────────────────────────────────────────────┘
```

- **Builders** only write rules into the accumulator. Presets write KU / EKU / BC /
  validity / default subject-SAN rules on construction.
- **`IssuancePolicy`** is the frozen artifact (`build()`), analogous to `CsrResult`.
  It is immutable and reusable across many CSRs.
- **Engine** has no fluent surface. `check` is the public façade; `evaluate` is
  what `CertificateIssuer` calls. One path for “accept this CSR?” and “materialize
  the certificate fields.”

Façade (`policy`): `PolicyBuilder`, `IssuancePolicy`, `FieldRule`, `Rules`, `ValidityRule`,
`CallerValues`, `PolicyViolationException`, `PolicyViolation`, `ViolationCodes`.
Builders (`policy.builder`): `HttpsPolicyBuilder` (no type-state on presets),
`ClientAuthPolicyBuilder`, `SigningPolicyBuilder`, `CustomPolicyStart`,
`CustomPolicyBuildable`, `CustomPolicyBuilder`, `SubjectRuleBuilder`, `SanRuleBuilder`,
`RawPolicy`, `RawPolicyImpl`.
Restrictions (`policy.restriction`): `RestrictionRule`, `RestrictionRules`,
`RestrictionOutcome`, `RestrictionSnapshot`.
Snapshot (`policy.snapshot`): `PolicySnapshot`, `PolicyCodec`.
Engine (`policy.engine`): `PolicyAccumulator`, `PolicyEngine`, `CsrView`, `Evaluation`.

The type is named **`IssuancePolicy`**, not `CertificatePolicy`. In X.509,
`CertificatePolicies` is an extension with policy OIDs. That extension, if needed, goes
through `RawPolicy`. Calling our object `CertificatePolicy` would be a footgun.

---

## Public API

Factory, parallel to `CsrBuilder`:

```java
PolicyBuilder.httpsPolicy()       // → HttpsPolicyBuilder
PolicyBuilder.clientAuthPolicy()  // → ClientAuthPolicyBuilder
PolicyBuilder.signingPolicy()     // → SigningPolicyBuilder
PolicyBuilder.custom()            // → CustomPolicyStart
```

Every `build()` returns an immutable `IssuancePolicy`.

```java
IssuancePolicy policy = PolicyBuilder.httpsPolicy().build();

policy.check(csr);            // PKCS10CertificationRequest
policy.check(csrPem);         // PEM string
policy.check(csr, caller);    // with sign-time overrides
```

### Policy builders

Prebuilt policies set KeyUsage / ExtendedKeyUsage / BasicConstraints and a default
validity rule themselves. The user tightens identity and, if they want, validity sourcing
and min/max.

**TLS server** — SAN from the CSR is required (preset, not type-state: the builder is
immediately buildable). Curated methods: `commonName`, `organization`, `country`, `dns`,
`ip`, `crl`, `ocsp`, `caIssuers`, `validity`, `custom`.

```java
IssuancePolicy policy = PolicyBuilder.httpsPolicy().build();
```

```java
IssuancePolicy policy = PolicyBuilder.httpsPolicy()
        .commonName(fromCsr().optional())
        .organization(fromCsr().orDefault("Acme Corp"))
        .country(fromCsr().oneOf("CZ", "SK"))
        .dns(fromCsr().matching(".*\\.acme\\.com"))
        .ip(fromCsr().optional())
        .crl("http://crl.acme.com/acme.crl")
        .ocsp("http://ocsp.acme.com")
        .validity(ValidityRule.fromCsr()
                .orCaller()
                .orDefault(Duration.ofDays(90))
                .min(Duration.ofDays(1))
                .max(Duration.ofDays(398)))
        .build();
```

The first form already accepts a CSR produced by `CsrBuilder.httpsCsr()`. The second form
is the same preset with tighter identity rules.

**Client authentication** — CN-only is legitimate; SAN is optional. Curated methods:
`commonName`, `organization`, `country`, `dns`, `ip`, `crl`, `ocsp`, `caIssuers`,
`validity`, `custom`.

```java
IssuancePolicy policy = PolicyBuilder.clientAuthPolicy()
        .commonName(fromCsr())
        .organization(fromCsr().orCaller())
        .build();
```

**Signing certificate (intermediate CA).** SAN is forbidden by default. Curated methods:
`commonName`, `organization`, `country`, `pathLen`, `crl`, `ocsp`, `caIssuers`,
`validity`, `custom`.

```java
IssuancePolicy policy = PolicyBuilder.signingPolicy()
        .commonName(fromCsr().orDefault("Intermediate CA"))
        .organization(exactly("Acme Corp"))
        .pathLen(0)
        .validity(ValidityRule.fromCsr()
                .orDefault(Duration.ofDays(1825))
                .max(Duration.ofDays(3650)))
        .build();
```

| Policy                 | KeyUsage (CA-owned)                                              | EKU        | BasicConstraints      | SAN default                         | Default validity |
|------------------------|------------------------------------------------------------------|------------|-----------------------|-------------------------------------|------------------|
| `httpsPolicy()`        | digitalSignature + keyEncipherment (RSA) / digitalSignature (else) | serverAuth | CA=false, critical    | dns+ip from CSR, at least one required | 90 days       |
| `clientAuthPolicy()`   | digitalSignature                                                 | clientAuth | CA=false, critical    | dns+ip from CSR, optional           | 90 days          |
| `signingPolicy()`      | keyCertSign, cRLSign                                             | —          | CA=true, pathLen=0    | forbidden                           | 1825 days        |

KeyUsage for HTTPS is **adaptive at evaluation time**, from the CSR public key type — the
same rule as `httpsCsr()`. Client-auth and signing use a fixed KeyUsage.

`pathLen(0)` is the signing-policy default: the cert can issue end-entity certs, not
sub-CAs. `.pathLen(n)` or `.unboundedPathLen()` override it. An intermediate CA is still
a `signingPolicy()` cert — issue it with `using(parentCa, parentKey)`, not `selfSigned`.
A root that signs intermediates needs `.pathLen(1)` or `.unboundedPathLen()`. See
[issue/readme.md](../issue/readme.md#certificate-chain).

Default validity rule on presets (see [Validity](#validity)):

```text
ValidityRule.fromCsr().optional().orCaller().orDefault(<preset default>)
```

No min/max unless the caller sets them. `.validity(Duration)` is shorthand for
`ValidityRule.exactly(duration)` (CA-fixed lifetime, CSR request ignored).
`.validity(ValidityRule)` replaces the whole rule. There is no separate `maxValidity()`
method — the cap lives on the rule, like `matching` on a SAN.

### Revocation URLs

CRL distribution points and OCSP are CA-owned URIs. They are ordinary methods on **every**
builder, including presets — not an ASN.1 escape hatch.

```java
IssuancePolicy policy = PolicyBuilder.httpsPolicy()
        .crl("http://crl.acme.com/acme.crl")
        .ocsp("http://ocsp.acme.com")
        .caIssuers("http://ca.acme.com/acme.crt")
        .build();
```

```java
HttpsPolicyBuilder crl(String uri);
HttpsPolicyBuilder ocsp(String uri);
HttpsPolicyBuilder caIssuers(String uri);   // AIA caIssuers; same extension as OCSP
```

Rules:

- Repeatable: each call appends a URI. Two `.crl(...)` calls write two distribution
  points.
- Blank or null is rejected at the builder (`IllegalArgumentException`), not at `check`.
- Omitted means the extension is **not** written. There is no default URL.
- Never sourced from the CSR. A CSR that requests CRLDP / AIA is an unknown
  `extensionRequest` and fails closed unless `RawPolicy.ignoreCsrExtension(...)`.
- Criticality is fixed: both extensions are **non-critical** (the usual CA profile).
- The engine emits:
  - `.crl(...)` → `cRLDistributionPoints` (each URI as a `DistributionPoint` fullName
    of type `uniformResourceIdentifier`)
  - `.ocsp(...)` / `.caIssuers(...)` → one `authorityInfoAccess` with
    `id-ad-ocsp` and/or `id-ad-caIssuers` access methods
- If only OCSP is set, AIA contains only OCSP. If neither OCSP nor caIssuers is set,
  AIA is omitted.

`caIssuers` is the other common AIA URI (where to fetch the issuing CA certificate). It
is the same class of “just a URL” as OCSP, so it sits next to it rather than in
`RawPolicy`.

LDAP and HTTPS URIs are allowed; the library does not fetch them and does not restrict
the scheme beyond “non-blank string”. A caller who needs reasons flags, CRLissuer, or
partitioned CRLs uses `RawPolicy.addExtension`.

### Field rules

Every identity method takes a `FieldRule`. Static factories live on `Rules` so examples
can `import static com.tbr.pki.tseal.policy.Rules.*`.

```java
public final class Rules {
    private Rules() {}

    public static FieldRule fromCsr() { ... }
    public static FieldRule exactly(String value) { ... }
    public static FieldRule forbidden() { ... }
    public static FieldRule ignoreCsr() { ... }
}

public final class FieldRule {
    public FieldRule optional();
    public FieldRule orCaller();
    public FieldRule orDefault(String value);
    public FieldRule matching(String regex);   // built-in RestrictionRule "regex"
    public FieldRule oneOf(String... allowed);
    public FieldRule maxLength(int n);
    public FieldRule restrict(RestrictionRule rule); // lambda, method ref, or registered type
    public FieldRule minEntries(int n);
    public FieldRule maxEntries(int n);        // subject and SAN; subject default max is 1
}
```

Meaning of the factories:

| Rule | CSR has a value | CSR lacks a value | Written on the cert |
|------|-----------------|-------------------|---------------------|
| `fromCsr()` | used, must pass constraints | **fail** | CSR value |
| `fromCsr().optional()` | used, must pass constraints | ok | CSR value, or omitted |
| `fromCsr().orCaller()` | used | caller, else **fail** | CSR or caller |
| `fromCsr().orDefault("x")` | used | `"x"` | CSR or default |
| `fromCsr().orCaller().orDefault("x")` | used | caller, else `"x"` | CSR, caller, or default |
| `exactly("x")` | **ignored** (not a violation) | n/a | always `"x"` |
| `ignoreCsr().orCaller().orDefault("x")` | **ignored** | caller, else `"x"` | caller or default |
| `forbidden()` | **fail** | ok | omitted |

Fluent order of `orCaller()` / `orDefault()` / constraints does **not** change precedence.
Evaluation is always:

```
CSR → caller → default
```

Constraints (`matching`, `oneOf`, `maxLength`, `maxEntries`) apply to the **winning**
value, and also to a CSR value even when a fallback exists: a present-but-illegal CSR
value is a violation, not a reason to fall through.

SAN fields are lists. For `dns` / `ip` / `email`:

- `fromCsr()` copies every CSR entry of that type; each must pass constraints; at least
  one entry is required unless `.optional()`.
- `orCaller()` **unions** caller entries of that type with the CSR entries, then
  validates each. Default applies only when the union is empty.
- `exactly("a.example.com")` writes that one name and ignores CSR/caller names of that
  type.
- `maxEntries(n)` / `minEntries(n)` apply after union. On **subject** RDNs, omitted
  `maxEntries` means 1 (at most one CN unless you raise it). On SAN, omitted means
  unlimited.
- `restrict(RestrictionRule)` or `restrict("typeName")` — see [Custom restrictions](#custom-restrictions).

### Custom restrictions

Built-ins (`regex`, `oneOf`, `maxLength`, `country`) need no registration. Anything else
is a named callable you bind **in process** — a lambda, a method reference, or a Spring
bean method. There is no plugin JAR / ServiceLoader.

**1. Boolean bean method** (typical Spring service):

```java
@Service
public class AcmeDnsChecker {
    public boolean isAllowed(String dns) {
        return dns != null && dns.endsWith(".acme.com");
    }
}

@Configuration
public class TsealRestrictions {
    @Bean
    RestrictionRules restrictionRules(AcmeDnsChecker checker) {
        return RestrictionRules.builtin()
                .bind("acmeDns", checker::isAllowed, "value.acmeDns", "DNS not on allowlist");
    }
}
```

**2. Method that returns `RestrictionOutcome`:**

```java
RestrictionRules.builtin()
        .bind("acmeDns", checker::evaluate);
```

**3. Use the name on a field rule and in JSON:**

```java
PolicyBuilder.httpsPolicy()
        .dns(fromCsr().restrict("acmeDns"))
        .build();
```

```json
"dns": {
  "mode": "fromCsr",
  "restrictions": [ { "type": "acmeDns" } ]
}
```

`bind` registers immediately for JSON and `restrict("acmeDns")`. Anonymous
`.restrict(v -> …)` still works for in-memory policies; it cannot be snapshotted — bind
a name if the policy must go through JSON.

`.country(...)` additionally encodes as PrintableString and, unless `matching` / `oneOf`
is already set, applies `[A-Z]{2}`. That is the policy-layer counterpart of the CSR
builder’s country encoding.

### Validity

Validity uses the **same sourcing model** as identity fields: CSR, then caller, then
default. Constraints are `min` / `max` on the lifetime (`Duration`), not regex.

PKCS#10 has no standard validity field. `ValidityRule.fromCsr()` reads a **requested
lifetime** from a library-defined non-critical CSR extension (ASN.1 `INTEGER` seconds,
OID `Oids.REQUESTED_VALIDITY`). The CSR builder writes it via `.validity(Duration)` —
see the CSR doc. Absolute `notBefore` / `notAfter` are not stored; the CA still sets
`notBefore` at sign time.

`ValidityRule` is a separate type from `FieldRule` so `Rules.fromCsr()` (strings) and
`ValidityRule.fromCsr()` (durations) do not clash under static import.

```java
public final class ValidityRule {
    public static ValidityRule fromCsr() { ... }
    public static ValidityRule exactly(Duration duration) { ... }
    public static ValidityRule forbidden() { ... }

    public ValidityRule optional();
    public ValidityRule orCaller();
    public ValidityRule orDefault(Duration duration);
    public ValidityRule min(Duration min);   // inclusive; reject if winning < min
    public ValidityRule max(Duration max);   // inclusive; reject if winning > max
}
```

On every builder, including presets:

```java
.validity(ValidityRule rule)
.validity(Duration duration)   // shorthand for ValidityRule.exactly(duration)
```

```java
PolicyBuilder.httpsPolicy()
        .validity(ValidityRule.fromCsr()
                .orCaller()
                .orDefault(Duration.ofDays(90))
                .min(Duration.ofDays(1))
                .max(Duration.ofDays(398)))
        .build();
```

| Rule | CSR has a requested lifetime | CSR lacks it | Written on the cert |
|------|------------------------------|--------------|---------------------|
| `fromCsr()` | used, must pass min/max | **fail** | that duration |
| `fromCsr().optional()` | used, must pass min/max | fall through | CSR, else omitted until fallback |
| `fromCsr().orCaller()` | used | caller, else **fail** | CSR or caller |
| `fromCsr().orDefault(d)` | used | `d` | CSR or default |
| `fromCsr().orCaller().orDefault(d)` | used | caller, else `d` | CSR, caller, or default |
| `exactly(d)` | **ignored** (not a violation) | n/a | always `d` |
| `forbidden()` | **fail** | ok | not from CSR; still needs `orCaller()` / `orDefault(d)` — a cert cannot omit validity |

Sourcing precedence is the same fixed chain: **CSR → caller → default**. Fluent order
does not change it. Min/max apply to the **winning** duration. A present-but-illegal CSR
lifetime is a violation, not a reason to fall through.

**Reject, do not clamp.** A request of 400 days against `max(398 days)` fails `check`.
The engine does not silently issue 398 days. Silent shortening is a different product
choice; v1 does not do it. To force a lifetime, use `exactly(...)`. To accept only one
lifetime from the CSR, use `fromCsr().min(d).max(d)` with the same `d`.

Builder-time errors (`IllegalArgumentException`), not `check`:

- null, zero, or negative `Duration` on `exactly` / `orDefault` / `min` / `max`
- `min > max`
- `forbidden()` with neither `orCaller()` nor `orDefault(...)` (a cert must have a lifetime)

Preset default (immediately buildable, existing CSRs without a requested lifetime still
pass):

| Policy | Default rule |
|--------|----------------|
| `httpsPolicy()` / `clientAuthPolicy()` | `fromCsr().optional().orCaller().orDefault(90 days)` |
| `signingPolicy()` | `fromCsr().optional().orCaller().orDefault(1825 days)` |

The requested-validity CSR extension is **owned** by every issuance policy (read or
ignored according to the rule). It is never an “unknown extension” fail-closed hit,
including when the rule is `exactly(...)`.

`custom()` has no validity default: `.validity(...)` is the type-state that unlocks
`build()`, and it accepts either a `Duration` or a `ValidityRule`.

The signer still picks absolute `notBefore` (clock, optional skew) and
`notAfter = notBefore + winning duration`. Validity in the policy is a **lifetime**, not
a pair of timestamps.

### Checking a CSR

Step 2 is useful without a signer:

```java
KeyPair kp = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
CsrResult csr = CsrBuilder.httpsCsr()
        .commonName("app")
        .dns("app.acme.com")
        .build(kp);

IssuancePolicy policy = PolicyBuilder.httpsPolicy()
        .dns(fromCsr().matching(".*\\.acme\\.com"))
        .build();

policy.check(csr.request());   // ok
policy.check(csr.pem());       // same
```

`check` collects **all** violations, then throws:

```java
public final class PolicyViolationException extends RuntimeException {
    public List<PolicyViolation> violations() { ... }
}

public record PolicyViolation(String field, String message) {}
```

`field` is dotted and stable: `subject.CN`, `subject.O`, `subject.C`, `san.dNSName`,
`san.iPAddress`, `extension.request.<oid>`, `unknown.subject.<oid>`, `validity`.
`code` is a machine token (`ViolationCodes`, e.g. `value.regex`, `san.unknown`) for API
error bodies.

`check` answers “would this CSR be accepted?”. It does not allocate a serial, issuer,
SKI, AKI, or signature — those belong to the signer.

### Caller values

Reusable policy, per-issuance fills. This type lives in the policy package so `orCaller()`
has something to read; the signer (step 3) will construct it.

```java
public final class CallerValues {
    public static CallerValues empty() { ... }
    public static CallerValues of() { ... }   // same as empty, for fluent start

    public CallerValues commonName(String cn);
    public CallerValues organization(String o);
    public CallerValues organizationalUnit(String ou);
    public CallerValues country(String c);
    public CallerValues dns(String dnsName);
    public CallerValues ip(String ipAddress);
    public CallerValues email(String emailAddress);
    public CallerValues validity(Duration lifetime);
}
```

```java
policy.check(csr.request(), CallerValues.of()
        .organization("Acme West")
        .dns("extra.acme.com")
        .validity(Duration.ofDays(30)));
```

`check(csr)` is `check(csr, CallerValues.empty())`. A rule with `orCaller()` and no
caller value behaves as if `orCaller()` was not enabled.

### Full customization

`custom()` exposes nested rule builders. Inner builders close with `and()`. `build()` is
reserved for the whole policy. **Validity has no default on `custom()`** — it is the one
type-state transition (`validity(Duration)` or `validity(ValidityRule)` unlocks
`build()`), analogous to HTTPS CSR requiring SAN.

```java
IssuancePolicy policy = PolicyBuilder.custom()
        .subject()
            .commonName(fromCsr())
            .organization(fromCsr().orDefault("Acme"))
            .organizationalUnit(fromCsr().optional())
            .country(fromCsr().oneOf("CZ"))
            .rdn(BCStyle.L, fromCsr().optional())
        .and()
        .san()
            .dns(fromCsr().required())   // equivalent to fromCsr(); explicit at this layer
            .ip(fromCsr().optional())
            .email(forbidden())
            .otherName(MS_UPN_OID, fromCsr().optional())
        .and()
        .keyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment)
        .extendedKeyUsage(KeyPurposeId.id_kp_serverAuth)
        .endEntity()
        .crl("http://crl.acme.com/acme.crl")
        .ocsp("http://ocsp.acme.com")
        .validity(ValidityRule.fromCsr()
                .orDefault(Duration.ofDays(90))
                .max(Duration.ofDays(398)))
        .build();
```

`SubjectRuleBuilder<P>`: `commonName`, `organization`, `organizationalUnit`, `country`,
`rdn(ASN1ObjectIdentifier, FieldRule)`.

`SanRuleBuilder<P>`: `dns`, `ip`, `email`, `otherName(ASN1ObjectIdentifier, FieldRule)`.

`fromCsr().required()` is an alias of `fromCsr()` so custom SAN reads clearly next to
`.optional()`.

CA-owned extensions on `custom()` — omitted means the extension is not written:

```java
CustomPolicyStart keyUsage(int bits);                    // critical
CustomPolicyStart extendedKeyUsage(KeyPurposeId... p);
CustomPolicyStart endEntity();                           // BC CA=false, critical
CustomPolicyStart ca(int pathLen);                       // BC CA=true, critical
CustomPolicyStart caUnbounded();                         // BC CA=true, no pathLen
CustomPolicyStart crl(String uri);                       // CRLDP, non-critical
CustomPolicyStart ocsp(String uri);                      // AIA OCSP, non-critical
CustomPolicyStart caIssuers(String uri);                 // AIA caIssuers, non-critical
```

There is **no** `keyUsage(fromCsr())`. Copying KU / EKU / BC from the CSR is the classic
“CSR asked to be a CA” footgun. If a caller truly needs it, `RawPolicy.copyExtensionFromCsr`
is the explicit, ugly path.

Type-state:

```java
public interface CustomPolicyStart {          // build() is NOT here
    SubjectRuleBuilder<CustomPolicyStart> subject();
    SanRuleBuilder<CustomPolicyStart> san();
    CustomPolicyStart keyUsage(int bits);
    CustomPolicyStart extendedKeyUsage(KeyPurposeId... purposes);
    CustomPolicyStart endEntity();
    CustomPolicyStart ca(int pathLen);
    CustomPolicyStart caUnbounded();
    CustomPolicyStart crl(String uri);
    CustomPolicyStart ocsp(String uri);
    CustomPolicyStart caIssuers(String uri);
    CustomPolicyStart custom(Consumer<RawPolicy> customizer);
    CustomPolicyBuildable validity(Duration duration);
    CustomPolicyBuildable validity(ValidityRule rule);
}

public interface CustomPolicyBuildable {      // build() IS here
    // same mutation methods, returning CustomPolicyBuildable
    IssuancePolicy build();
}
```

One impl class, two views — same trick as `HttpsStart` / `HttpsBuildable`.

### Escape hatch

Available on **every** builder via `.custom(Consumer<RawPolicy>)`:

```java
public interface RawPolicy {
    RawPolicy addExtension(ASN1ObjectIdentifier oid, boolean critical, ASN1Encodable value);
    RawPolicy copyExtensionFromCsr(ASN1ObjectIdentifier oid, boolean required);
    RawPolicy ignoreCsrExtension(ASN1ObjectIdentifier oid);
    RawPolicy allowSubjectRdn(ASN1ObjectIdentifier oid, FieldRule rule);
    RawPolicy allowSanType(int generalNameTag, FieldRule rule);
}
```

- `addExtension` — CA-owned extension, always written (nameConstraints, X.509
  certificatePolicies, partitioned CRLDP, …). Ordinary CRL / OCSP / caIssuers URIs do
  **not** belong here.
- `copyExtensionFromCsr` — copy that OID from the CSR’s `extensionRequest`; `required`
  fails if missing. Opt-in, never a preset default.
- `ignoreCsrExtension` — do not copy, do not fail if present (already the implicit
  behaviour for KU / EKU / BC on presets).
- `allowSubjectRdn` / `allowSanType` — extend the allow-list on a preset without switching
  to `custom()`.

Example — name constraints on a signing policy; CRL/OCSP stay typed:

```java
PolicyBuilder.signingPolicy()
        .crl("http://crl.acme.com/acme.crl")
        .ocsp("http://ocsp.acme.com")
        .custom(raw -> raw.addExtension(Extension.nameConstraints, true, nameConstraints))
        .build();
```

---

## What a preset actually puts on the certificate

The engine, at **evaluation / sign time**, materializes fields as follows.

**Copied from the CSR (if the rule says so):** subject RDNs on the allow-list, SAN
entries on the allow-list, requested lifetime, the subject public key.

**Never copied from the CSR (presets):** KeyUsage, ExtendedKeyUsage, BasicConstraints,
CRLDP, AIA. Our own `CsrBuilder` writes KU / EKU / BC onto the CSR; the CA still
overwrites them. Their presence in the CSR is **not** a violation. CRLDP / AIA are not
emitted by `CsrBuilder`; if a CSR requests them they fail closed (unknown extension)
unless ignored via `RawPolicy`.

**Never copied, not a violation:** PKCS#9 / Microsoft enrollment attributes
(`challengePassword`, certificate template, …). They are not certificate fields.

**Sourced like identity (CSR → caller → default), in this object:** validity **lifetime**.
Min/max are constraints on that lifetime. Absolute `notBefore` / `notAfter` are still
applied by the signer from a `Clock`.

**CA-owned, in this object:** CRL / OCSP / caIssuers URIs, KU / EKU / BC.

**CA-owned, not in this object:** issuer, serial, SKI, AKI, signature algorithm (derived
from the **CA** key by the signer, same tables as CSR).

**Fail closed:**

- Subject RDN present in the CSR but not mentioned in the policy.
- SAN type present in the CSR but not mentioned in the policy.
- `extensionRequest` OID that the policy neither owns, copies, nor ignores.
  The requested-lifetime OID is always owned (see [Validity](#validity)).

So a CSR built with `CsrBuilder.httpsCsr().commonName(...).dns(...).build(kp)` passes
`httpsPolicy()`: CN is allowed (optional), dns SAN is required and present, KU/EKU/BC
are ignored as CSR extensions and rewritten from the policy.

A CSR that also has `email` in the SAN fails `httpsPolicy()` until the policy says
`.custom(raw -> raw.allowSanType(GeneralName.rfc822Name, fromCsr().optional()))`.

---

## Key design decisions

### Allow-list, not silent drop

Dropping unknown RDNs/SAN types/extensions without error looks convenient and produces
certificates the requester did not expect. v1 **rejects** anything not mentioned. Presets
must therefore declare the fields they are willing to copy (HTTPS: CN optional, dns+ip
SAN). Exotic identity goes through `RawPolicy.allowSubjectRdn` / `allowSanType` or
`custom()`.

### CA is authoritative for KU / EKU / BasicConstraints / CRL / OCSP

A leaf CSR that requests `CA=true` / `keyCertSign` must not become a CA. Presets always
write their own KU / EKU / BC. CSR copies of those extensions are ignored, not compared
and not rejected — comparison would break our own CSR builder, which always emits them.

CRL and OCSP URLs are CA-owned: the requester does not get to pick them. They are typed
`String` methods, not `FieldRule`s, because there is no legitimate “copy CRLDP from the
CSR” path on a well-behaved CA. Validity is the opposite: a requester *does* often ask
for a lifetime, so it uses `ValidityRule` like identity uses `FieldRule`.

### CRL and OCSP are typed URIs, not RawPolicy

Almost every real profile needs a CRL URL, an OCSP URL, or both. Requiring
`DistributionPoint` / `AccessDescription` ASN.1 for that violates “easy things easy.”
`.crl(url)` / `.ocsp(url)` / `.caIssuers(url)` write the usual non-critical extensions.
Partitioned CRLs, reasons flags, and other AIA access methods stay on `RawPolicy`.

### Fixed fallback order

`CSR → caller → default`. The fluent chain only *enables* fallbacks. There is no
`callerThenCsr()` and no way for call order to invert precedence. SAN is the one
structural exception: caller values are **unioned** with CSR values, because “operator
adds a SAN” is the real use of `orCaller()` on a list.

A CSR value that fails constraints does not fall through to caller/default.

### Validity is a lifetime with min/max, not timestamps

The policy stores a `Duration`, sourced CSR → caller → default. `min` / `max` reject
out-of-range lifetimes; they do not clamp. Absolute dates are signer-owned so a CSR
cannot pick `notBefore` in 2099. PKCS#10 has no standard validity, so `fromCsr()` reads
`Oids.REQUESTED_VALIDITY`; the CSR builder writes it with `.validity(Duration)`.

### `exactly` ignores the CSR; `forbidden` rejects it

If the CA always stamps `O=Acme`, CSR `O=Evil` is overwritten, not a violation. If the
CA does not allow an email SAN, a CSR email SAN is a violation. Those are different
intents and different factories.

### Type-state is still surgical

Presets are immediately buildable (they have validity and SAN defaults). The only
type-state in this module is **`custom()` requiring `validity(...)`** before `build()`.
A custom policy with no dates would emit an invalid cert; that is the same class of
mistake as an HTTPS CSR with no SAN.

### Policy does not sign

`IssuancePolicy` has no key, no issuer, no `ContentSigner`. Issuance lives on
`CertificateIssuer` — see [issue/readme.md](../issue/readme.md):

```java
IssuedCertificate cert = CertificateIssuer.issue()
        .csr(csr)
        .policy(policy)
        .using(caCert, caKey)
        .issue();
```

The issuer calls the same `PolicyEngine.evaluate(...)` that `check` uses, then attaches
issuer, serial, SKI, AKI, and the CA signature.

### `check` collects every violation

Issuance failures are expected (bad CSRs). Fail-fast on the first field is hostile.
The engine accumulates `PolicyViolation`s and throws once.

### No decorator

Motivation originally mentioned decorating policies. The CSR module already replaced that
with curated builders + `custom()` + escape hatch. This module does the same. Layering
is composition of rules on one accumulator, not a decorator chain.

---

## Out of scope

This module does not issue certificates. Issuance is [step 3](../issue/readme.md).
Still out of scope **here**:

- **Signing / PKCS provider / HSM.** `CertificateIssuer` plus `ContentSigner`.
- **Serial, issuer, SKI, AKI, notBefore clock-skew policy.** Issuer-owned. `check`
  evaluates the validity **rule** (sourcing + min/max) against the CSR and caller; it
  does not need a clock for that. The issuer applies a `Clock` when turning the winning
  duration into `notBefore` / `notAfter`.
- **Clamping** a requested lifetime to `max`. v1 rejects. Use `exactly` to force a
  duration.
- **Copying KU / EKU / BC from the CSR as a typed API.** Escape hatch only.
- **Partitioned CRLs, reasons flags, non-URI distribution points, extra AIA access
  methods.** Typed API is URI-only. Everything else is `RawPolicy.addExtension`.
- **X.509 CertificatePolicies extension and name constraints as typed methods.**
  Escape hatch in v1 (YAGNI).
- **SCEP/EST/ACME.** Transport is the caller’s concern.
- **Phase 2 certificate validation.** A validation policy may share rule types later;
  this object is an *issuance* profile, not a chain validator.
- **Matching a CSR signature / proof-of-possession.** The issuer verifies the CSR
  signature; `check` does not (it has no reason to).

NotBefore backdate (default 5 minutes) is an issuer default, not a policy field. See
[issue/readme.md](../issue/readme.md).

---

## Resolved decisions

1. **Name.** Public type is `IssuancePolicy`. Factory is `PolicyBuilder` with
   `httpsPolicy()` / `clientAuthPolicy()` / `signingPolicy()` / `custom()`, parallel to
   `CsrBuilder`.
2. **Artifact.** `build()` returns an immutable reusable policy, not a certificate.
   Independent usefulness is `check(...)`.
3. **Sourcing.** `fromCsr` / `exactly` / `forbidden` / `ignoreCsr`, plus `optional` / `orCaller` /
   `orDefault` / constraints. Precedence is fixed: CSR → caller → default.
4. **Allow-list.** Unexpected subject RDNs, SAN types, and requested extensions fail.
   KU / EKU / BC in the CSR are ignored. Enrollment attributes are ignored.
5. **CA-owned KU / EKU / BC** on presets; adaptive HTTPS KeyUsage at evaluation time
   from the CSR public key, same as the CSR engine.
6. **CRL / OCSP / caIssuers** are typed, repeatable URI methods on every builder.
   CA-owned, non-critical, omitted if unset. Not `FieldRule`s. Not RawPolicy.
7. **Validity.** Same sourcing as identity: `ValidityRule.fromCsr()` / `orCaller()` /
   `orDefault` / `exactly` / `forbidden`, plus `min` / `max`. Reject, do not clamp.
   Lifetime only; absolute dates are signer-owned. Presets:
   `fromCsr().optional().orCaller().orDefault(90d leaf / 1825d signing)`. `custom()`
   requires `.validity(...)` via type-state. No default 398-day cap. `.validity(Duration)`
   is `exactly`. Requested lifetime is a CSR extension the policy always owns.
8. **Signing pathLen.** Default `0`. Override with `pathLen(n)` or `unboundedPathLen()`.
9. **Sub-builders.** `SubjectRuleBuilder` / `SanRuleBuilder` live only on `custom()`.
   Presets stay curated (`commonName`, `organization`, `country`, `dns`, `ip`, `crl`,
   `ocsp`, …); exotic identity goes through `RawPolicy`.
10. **No `fromCsr` for KU / EKU / BC** on the typed API.
11. **Escape hatch** is `.custom(Consumer<RawPolicy>)` on every builder, same placement
    as `RawCsr`.
12. **No decorator.**

---

## Serialization

`IssuancePolicy.snapshot()` / `fromSnapshot` is the format-agnostic interchange.
JSON is module `:tseal-policy-json` so `:tseal` stays Bouncy Castle–only.
Schema version 2 (`extends`, `restrictions`). Version 1 documents still read.
See [serde.md](serde.md).

---

*Certificate signing is a separate document (Phase 1 step 3).*
