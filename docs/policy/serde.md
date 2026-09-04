# Policy serialization

An `IssuancePolicy` can be written to a document and read back. The interchange type is
`PolicySnapshot` in `com.tbr.pki.tseal.policy.snapshot` (no JSON library). Formats
implement `PolicyCodec` in the same package.

Jackson is **not** a core dependency. JSON lives in the `tseal-policy-json` module.

```
IssuancePolicy ──snapshot()──► PolicySnapshot
                                     │
                            PolicyCodec (SPI)
                                     │
                              JsonPolicyCodec
```

## JSON module

Coordinates: `com.tbr.pki.tseal:tseal` (core) and `com.tbr.pki.tseal:tseal-policy-json`
(Gradle `:tseal` / `:tseal-policy-json`). The root project is an aggregator only.

```java
PolicyCodec json = new JsonPolicyCodec();

String text = json.write(policy);
IssuancePolicy restored = json.read(text);

json.write(policy, Path.of("https-policy.json"));   // JsonPolicyCodec only
IssuancePolicy fromFile = json.read(Path.of("https-policy.json"));
```

Pretty-printed by default. Unknown JSON properties are ignored. Empty collections and
`false` flags are omitted.

**Schema version.** `version` is the document schema. Writers emit `2`. Readers accept
`1` and `2`. Higher versions are rejected. Version 1 documents (`matching` / `oneOf` /
`maxLength` on field rules, no `restrictions` / `extends`) still load.

A document **must** include `validity` after merge. Presets already have a default rule,
and that rule is written out (`"orDefault": "P90D"` for HTTPS). Hand-written JSON that
omits `validity` is rejected; the library does not guess 90 days.

`extends` is a document id. Resolve it with `JsonPolicyCodec.read(json, id -> …)`. Overlay
keys replace; `subject` / `san` / `otherNames` merge per key.

```json
{
  "version" : 2,
  "subject" : {
    "CN" : {
      "mode" : "fromCsr",
      "optional" : true
    }
  },
  "san" : {
    "dns" : {
      "mode" : "fromCsr",
      "optional" : true
    },
    "ip" : {
      "mode" : "fromCsr",
      "optional" : true
    }
  },
  "atLeastOneSan" : true,
  "validity" : {
    "mode" : "fromCsr",
    "optional" : true,
    "orCaller" : true,
    "orDefault" : "P90D"
  },
  "keyUsage" : {
    "adaptive" : true
  },
  "extendedKeyUsage" : [ "1.3.6.1.5.5.7.3.1" ],
  "basicConstraints" : {
    "endEntity" : true
  }
}
```

| Field | Notes |
|-------|--------|
| `version` | Schema: write 2, read 1–2 |
| `extends` | Base document id; requires `PolicyDocumentResolver` |
| `subject` keys | `CN`, `O`, `OU`, `C`, `L`, `ST`, `E`, or a dotted OID |
| `san` keys | `dns`, `ip`, `email`, `uri`, `otherName`, or a `GeneralName` tag number |
| `otherNames` | map of otherName type OID → field rule |
| rule `mode` | `fromCsr`, `exactly`, `forbidden`, `ignoreCsr` |
| `restrictions` | `[{ "type", "params", "values" }]`. Built-ins: `regex`, `oneOf`, `maxLength`, `country`. Custom types: `RestrictionRules.builtin().bind("name", bean::isAllowed)` |
| `minEntries` / `maxEntries` | Cardinality (subject default max is 1) |
| durations | ISO-8601 (`P90D`, `PT12H`) |
| extra extensions | `{ "oid", "critical", "der" }` — Base64 DER of the ASN.1 value |

Another format (YAML, …) implements `PolicyCodec` and reads/writes `PolicySnapshot`. Do
not add that library to core.

Core-only round-trip, no JSON:

```java
IssuancePolicy restored = policy.snapshot().toPolicy();
```
