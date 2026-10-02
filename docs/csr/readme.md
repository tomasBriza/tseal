# CSR builder

PKCS#10 requests. Packages: `io.github.tomasbriza.tseal.csr`, `.builder`, `.engine`. Keys: `io.github.tomasbriza.tseal.key`.

Builders write a `CsrAccumulator`. `CsrEngine` is the only Bouncy Castle path: one `extensionRequest` attribute, signature, PEM. `build` returns `CsrResult(PKCS10CertificationRequest request, String pem)`.

Factories: `httpsCsr()` (`HttpsStart`, `dns()` or `ip()` moves to `HttpsBuildable`), `clientAuthCsr()`, `signingCsr()`, `custom()`.

## Presets

Identity is caller-supplied. KU / EKU / BasicConstraints are written by the preset.

| Builder           | KeyUsage                                                                     | EKU        | BasicConstraints | Required        |
|-------------------|------------------------------------------------------------------------------|------------|------------------|-----------------|
| `httpsCsr()`      | adaptive: RSA `digitalSignature \| keyEncipherment`, else `digitalSignature` | serverAuth | CA=false         | SAN, type-state |
| `clientAuthCsr()` | digitalSignature                                                             | clientAuth | CA=false         | none            |
| `signingCsr()`    | keyCertSign, cRLSign                                                         | —          | CA=true          | none            |

`httpsCsr()` stores `adaptiveKeyUsage`. The engine writes KeyUsage from the public key at `build`. Client-auth and signing write a fixed KeyUsage in the constructor.

HTTPS: `build()` is on `HttpsBuildable` only. `dns()` and `ip()` transition to it. `commonName`, `validity`, and `custom` do not, even if the callback adds a SAN. Client-auth and signing are flat. An empty subject is allowed.

Curated methods: HTTPS `commonName`, `dns`, `ip`, `validity`, `custom`. Client-auth and signing: `commonName`, `organization`, `validity`, `custom`.

## Keys

`KeyPairFactory.generate(KeyAlgorithm)`. Values: `RSA_2048`, `RSA_3072`, `RSA_4096`, `EC_P256`, `EC_P384`, `EC_P521`, `ED25519`, `ED448`. Provider `BC`, registered on first use if absent.

No `build(PrivateKey)`. The engine does not derive a public key. Terminals: `build(KeyPair)`, `build(PublicKey, PrivateKey)`, `build(PublicKey, ContentSigner)`.

Signer, first match:

1. `build(PublicKey, ContentSigner)`
2. `RawCsr.contentSigner(...)`
3. `JcaContentSignerBuilder` with `RawCsr.signatureAlgorithm(...)`, or the table below

Paths 1 and 2 skip derivation. A mismatched signer fails at build or verify.

| Public key               | Algorithm                                           |
|--------------------------|-----------------------------------------------------|
| RSA                      | SHA256withRSA                                       |
| EC P-256 / P-384 / P-521 | SHA256withECDSA / SHA384withECDSA / SHA512withECDSA |
| other EC                 | SHA256withECDSA                                     |
| Ed25519 / Ed448          | Ed25519 / Ed448                                     |

EC size is `ECPublicKey.getParams().getCurve().getField().getFieldSize()`. Other algorithms throw `IllegalArgumentException`. RSA-PSS is only via `ContentSigner`.

## `custom()`

Inner builders close with `and()`. `build(...)` is only the CSR.

`SubjectBuilder`: `commonName`, `organization`, `organizationalUnit`, `country`, `rdn(oid, ASN1Encodable)`. `SanBuilder`: `dns`, `ip`, `email`, `otherName(oid, ASN1Encodable)`. Both are only on `custom()`. Presets stay on the curated methods; other OIDs go through `RawCsr`.

DN uses `X500NameBuilder(BCStyle.INSTANCE)`. Most RDNs are UTF8String. `country(...)` is `DERPrintableString`. No name-style hook and no two-letter check.

`CustomCsrBuilder` also has `keyUsage(int)` (critical), `extendedKeyUsage(...)` (non-critical), `validity(Duration)`. No preset BasicConstraints; add it with `RawCsr.addExtension`.

## `RawCsr`

`.custom(Consumer<RawCsr>)` on every builder. Methods: `addAttribute(oid, value)`, `addExtension(oid, critical, value)`, `subjectRdn(oid, value)`, `signatureAlgorithm(jcaName)`, `contentSigner(signer)`.

## Requested validity

PKCS#10 has no notBefore/notAfter. `.validity(Duration)` on every builder writes a non-critical extension the issuance policy can read. It does not unlock HTTPS `build()`.

OID `Oids.REQUESTED_VALIDITY` = `2.25.202374478988983660858747592558420250208` (UUID arc, name `io.github.tomasbriza.tseal.requested-validity`). Value: ASN.1 `INTEGER` seconds. The CA still chooses `notBefore`.

Null, negative, zero, or `< 1s` throws `IllegalArgumentException` at the call. A later call replaces the previous value.

## Engine finalization

Before signing, `CsrEngine`:

1. If `adaptiveKeyUsage`, add critical KeyUsage from the public key type.
2. If any SAN was collected, add non-critical SAN.
3. If `validity` was set, add `Oids.REQUESTED_VALIDITY`.

An empty extension generator writes no `extensionRequest`. `addAttribute` values are always copied.

Out of scope here: issuance, SCEP/EST/ACME, key storage, CA business rules. HSM signing is `build(publicKey, signer)` only. Keystore load/store: [keystore/readme.md](../keystore/readme.md).
