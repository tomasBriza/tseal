# Policy serialization

Core type is `PolicySnapshot` (`io.github.tomasbriza.tseal.policy.snapshot`). `PolicyCodec` is the SPI: `write(IssuancePolicy)` and `read(String)`. Jackson is not a core dependency.

`IssuancePolicy.snapshot()` produces a `PolicySnapshot`. `PolicySnapshot.toPolicy()` restores it with no codec.

JSON: `io.github.tomasbriza:tseal-policy-json`, class `JsonPolicyCodec`. `read` / `write` on `String`. `read` / `write` on `Path` throw `IOException`. `read(document, PolicyDocumentResolver)` and `read(path, resolver)` resolve `extends`. Pretty-printed. Unknown properties ignored. Empty collections and `false` omitted.

`version` is the schema. Writers emit `2`. Readers accept `1` and `2`. Anything higher throws. Version 1 has `matching` / `oneOf` / `maxLength` on field rules and no `restrictions` or `extends`.

After `extends` merge, `validity` is required. Presets write their default (`"orDefault": "P90D"` for HTTPS). Omitted validity is rejected. The library does not insert 90 days.

`extends` is a document id. Overlay keys replace. `subject`, `san`, and `otherNames` merge per key.

| Field                       |                                                                                                                                                       |
|-----------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| `version`                   | write 2, read 1–2                                                                                                                                     |
| `extends`                   | base document id; needs `PolicyDocumentResolver`                                                                                                      |
| `subject` keys              | `CN`, `O`, `OU`, `C`, `L`, `ST`, `E`, or a dotted OID                                                                                                 |
| `san` keys                  | `dns`, `ip`, `email`, `uri`, `otherName`, or a `GeneralName` tag                                                                                      |
| `otherNames`                | otherName type OID → field rule                                                                                                                       |
| `mode`                      | `fromCsr`, `exactly`, `forbidden`, `ignoreCsr`                                                                                                        |
| `restrictions`              | `[{ "type", "params", "values" }]`. Built-ins: `regex`, `oneOf`, `maxLength`, `country`. Custom: `RestrictionRules.builtin().bind("name", predicate)` |
| `minEntries` / `maxEntries` | subject default max is 1                                                                                                                              |
| durations                   | ISO-8601 (`P90D`, `PT12H`)                                                                                                                            |
| extra extensions            | `{ "oid", "critical", "der" }` — Base64 DER of the extension value                                                                                    |

Another format implements `PolicyCodec` over `PolicySnapshot`. Do not add it to `:tseal`.
