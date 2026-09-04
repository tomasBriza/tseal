package com.tbr.pki.tseal.policy.snapshot;

import com.tbr.pki.tseal.policy.FieldRule;
import com.tbr.pki.tseal.policy.IssuancePolicy;
import com.tbr.pki.tseal.policy.ValidityRule;
import com.tbr.pki.tseal.policy.engine.PolicyAccumulator;
import com.tbr.pki.tseal.policy.restriction.RestrictionRules;
import com.tbr.pki.tseal.policy.restriction.RestrictionSnapshot;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Format-agnostic interchange for {@link IssuancePolicy}.
 * {@link #version} is the document schema: writers emit {@link #SCHEMA_VERSION};
 * readers accept 1 and 2.
 */
public record PolicySnapshot(
        int version,
        String extendsFrom,
        Map<String, FieldRuleSnapshot> subject,
        Map<String, FieldRuleSnapshot> san,
        Map<String, FieldRuleSnapshot> otherNames,
        Boolean atLeastOneSan,
        ValidityRuleSnapshot validity,
        KeyUsageSnapshot keyUsage,
        List<String> extendedKeyUsage,
        BasicConstraintsSnapshot basicConstraints,
        List<String> crl,
        List<String> ocsp,
        List<String> caIssuers,
        List<ExtensionSnapshot> extraExtensions,
        List<CopyFromCsrSnapshot> copyFromCsr,
        List<String> ignoreFromCsr
) {
    /** Schema written by this library. */
    public static final int SCHEMA_VERSION = 2;

    public PolicySnapshot {
        if (version == 0) {
            version = 1;
        }
        if (version < 1 || version > SCHEMA_VERSION) {
            throw new IllegalArgumentException("unsupported policy snapshot version: " + version);
        }
        subject = copyMap(subject);
        san = copyMap(san);
        otherNames = copyMap(otherNames);
        crl = copyList(crl);
        ocsp = copyList(ocsp);
        caIssuers = copyList(caIssuers);
        extendedKeyUsage = copyList(extendedKeyUsage);
        extraExtensions = copyList(extraExtensions);
        copyFromCsr = copyList(copyFromCsr);
        ignoreFromCsr = copyList(ignoreFromCsr);
    }

    public static PolicySnapshot from(IssuancePolicy policy) {
        Objects.requireNonNull(policy, "policy");
        PolicyAccumulator acc = policy.spec;

        Map<String, FieldRuleSnapshot> subject = new LinkedHashMap<>();
        acc.subjectRules.forEach((oid, rule) -> subject.put(subjectKey(oid), FieldRuleSnapshot.from(rule)));

        Map<String, FieldRuleSnapshot> san = new LinkedHashMap<>();
        acc.sanTypeRules.forEach((tag, rule) -> san.put(sanKey(tag), FieldRuleSnapshot.from(rule)));

        Map<String, FieldRuleSnapshot> otherNames = new LinkedHashMap<>();
        acc.otherNameRules.forEach((oid, rule) -> otherNames.put(oid.getId(), FieldRuleSnapshot.from(rule)));

        List<String> eku = null;
        if (acc.eku != null && acc.eku.length > 0) {
            eku = new ArrayList<>();
            for (KeyPurposeId id : acc.eku) {
                eku.add(id.getId());
            }
        }

        KeyUsageSnapshot keyUsage = null;
        if (acc.adaptiveKeyUsage) {
            keyUsage = new KeyUsageSnapshot(true, null);
        } else if (acc.keyUsageBits != null) {
            keyUsage = new KeyUsageSnapshot(null, acc.keyUsageBits);
        }

        BasicConstraintsSnapshot bc = null;
        if (acc.endEntity) {
            bc = new BasicConstraintsSnapshot(null, null, true);
        } else if (acc.ca) {
            bc = new BasicConstraintsSnapshot(true, acc.pathLen, null);
        }

        List<ExtensionSnapshot> extras = new ArrayList<>();
        for (var extra : acc.extraExtensions) {
            extras.add(ExtensionSnapshot.from(extra));
        }

        List<CopyFromCsrSnapshot> copies = new ArrayList<>();
        acc.copyFromCsr.forEach((oid, required) -> copies.add(new CopyFromCsrSnapshot(oid.getId(), required)));

        List<String> ignore = acc.ignoreCsrExtensions.stream().map(ASN1ObjectIdentifier::getId).toList();

        return new PolicySnapshot(
                SCHEMA_VERSION,
                null,
                subject,
                san,
                otherNames,
                acc.atLeastOneSan ? Boolean.TRUE : null,
                ValidityRuleSnapshot.from(acc.validity),
                keyUsage,
                eku,
                bc,
                List.copyOf(acc.crlUris),
                List.copyOf(acc.ocspUris),
                List.copyOf(acc.caIssuersUris),
                extras,
                copies,
                ignore
        );
    }

    /**
     * Overlay wins per present field. Maps merge per key. Non-empty overlay lists replace;
     * empty overlay lists inherit (JSON {@code "crl": []} is handled in the JSON codec).
     */
    public PolicySnapshot merge(PolicySnapshot overlay) {
        Objects.requireNonNull(overlay, "overlay");
        return new PolicySnapshot(
                SCHEMA_VERSION,
                null,
                mergeMaps(subject, overlay.subject),
                mergeMaps(san, overlay.san),
                mergeMaps(otherNames, overlay.otherNames),
                overlay.atLeastOneSan != null ? overlay.atLeastOneSan : atLeastOneSan,
                overlay.validity != null ? overlay.validity : validity,
                overlay.keyUsage != null ? overlay.keyUsage : keyUsage,
                replaceIfNonEmpty(extendedKeyUsage, overlay.extendedKeyUsage),
                overlay.basicConstraints != null ? overlay.basicConstraints : basicConstraints,
                replaceIfNonEmpty(crl, overlay.crl),
                replaceIfNonEmpty(ocsp, overlay.ocsp),
                replaceIfNonEmpty(caIssuers, overlay.caIssuers),
                replaceIfNonEmpty(extraExtensions, overlay.extraExtensions),
                replaceIfNonEmpty(copyFromCsr, overlay.copyFromCsr),
                replaceIfNonEmpty(ignoreFromCsr, overlay.ignoreFromCsr)
        );
    }

    public IssuancePolicy toPolicy() {
        if (validity == null) {
            throw new IllegalArgumentException("validity rule is required");
        }
        PolicyAccumulator acc = new PolicyAccumulator();
        subject.forEach((key, rule) -> acc.putSubject(parseSubjectOid(key), rule.toRule()));
        san.forEach((key, rule) -> acc.putSanType(parseSanTag(key), rule.toRule()));
        otherNames.forEach((oid, rule) -> acc.putOtherName(new ASN1ObjectIdentifier(oid), rule.toRule()));
        acc.atLeastOneSan = Boolean.TRUE.equals(atLeastOneSan);
        acc.setValidity(validity.toRule());

        if (keyUsage != null) {
            if (Boolean.TRUE.equals(keyUsage.adaptive())) {
                acc.adaptiveKeyUsage = true;
            } else if (keyUsage.bits() != null) {
                acc.keyUsageBits = keyUsage.bits();
            }
        }
        if (extendedKeyUsage != null && !extendedKeyUsage.isEmpty()) {
            acc.eku = extendedKeyUsage.stream()
                    .map(id -> KeyPurposeId.getInstance(new ASN1ObjectIdentifier(id)))
                    .toArray(KeyPurposeId[]::new);
        }
        if (basicConstraints != null) {
            if (Boolean.TRUE.equals(basicConstraints.endEntity())
                    || Boolean.FALSE.equals(basicConstraints.ca())) {
                acc.endEntity = true;
                acc.ca = false;
                acc.pathLen = null;
            } else if (Boolean.TRUE.equals(basicConstraints.ca())) {
                acc.ca = true;
                acc.endEntity = false;
                acc.pathLen = basicConstraints.pathLen();
            }
        }
        acc.crlUris.addAll(crl);
        acc.ocspUris.addAll(ocsp);
        acc.caIssuersUris.addAll(caIssuers);
        for (ExtensionSnapshot extra : extraExtensions) {
            acc.extraExtensions.add(extra.toExtension());
        }
        for (CopyFromCsrSnapshot copy : copyFromCsr) {
            acc.copyFromCsr.put(new ASN1ObjectIdentifier(copy.oid()), copy.required());
        }
        for (String oid : ignoreFromCsr) {
            acc.ignoreCsrExtensions.add(new ASN1ObjectIdentifier(oid));
        }
        return new IssuancePolicy(acc);
    }

    public record FieldRuleSnapshot(
            String mode,
            boolean optional,
            boolean orCaller,
            String exact,
            String orDefault,
            String matching,
            List<String> oneOf,
            Integer maxLength,
            Integer minEntries,
            Integer maxEntries,
            List<RestrictionSnapshot> restrictions
    ) {
        public FieldRuleSnapshot {
            oneOf = oneOf == null ? List.of() : List.copyOf(oneOf);
            restrictions = restrictions == null ? List.of() : List.copyOf(restrictions);
        }

        static FieldRuleSnapshot from(FieldRule rule) {
            if (rule.hasAnonymousRestriction()) {
                throw new IllegalArgumentException(
                        "cannot serialize anonymous restriction; RestrictionRules.register(type, rule) first");
            }
            List<RestrictionSnapshot> snaps = rule.restrictions.stream()
                    .map(RestrictionSnapshot::from)
                    .toList();
            return new FieldRuleSnapshot(
                    FieldRule.modeName(rule.mode),
                    rule.optional,
                    rule.orCaller,
                    rule.exactValue,
                    rule.defaultValue,
                    null,
                    List.of(),
                    null,
                    rule.minEntries,
                    rule.maxEntries,
                    snaps
            );
        }

        FieldRule toRule() {
            return FieldRule.fromSnapshot(
                    mode, optional, orCaller, exact, orDefault, matching,
                    oneOf, maxLength, minEntries, maxEntries, restrictions);
        }
    }

    public record ValidityRuleSnapshot(
            String mode,
            boolean optional,
            boolean orCaller,
            String exact,
            String orDefault,
            String min,
            String max
    ) {
        static ValidityRuleSnapshot from(ValidityRule rule) {
            return new ValidityRuleSnapshot(
                    ValidityRule.modeName(rule.mode),
                    rule.optional,
                    rule.orCaller,
                    ValidityRule.formatDuration(rule.exactValue),
                    ValidityRule.formatDuration(rule.defaultValue),
                    ValidityRule.formatDuration(rule.min),
                    ValidityRule.formatDuration(rule.max)
            );
        }

        ValidityRule toRule() {
            return ValidityRule.fromSnapshot(mode, optional, orCaller, exact, orDefault, min, max);
        }
    }

    public record KeyUsageSnapshot(Boolean adaptive, Integer bits) {}

    public record BasicConstraintsSnapshot(Boolean ca, Integer pathLen, Boolean endEntity) {}

    public record ExtensionSnapshot(String oid, boolean critical, String der) {
        static ExtensionSnapshot from(PolicyAccumulator.CaExtension extra) {
            try {
                byte[] encoded = extra.value().toASN1Primitive().getEncoded("DER");
                return new ExtensionSnapshot(
                        extra.oid().getId(), extra.critical(), Base64.getEncoder().encodeToString(encoded));
            } catch (IOException e) {
                throw new IllegalArgumentException("Failed to encode extension " + extra.oid(), e);
            }
        }

        PolicyAccumulator.CaExtension toExtension() {
            try {
                byte[] derBytes = Base64.getDecoder().decode(der);
                return new PolicyAccumulator.CaExtension(
                        new ASN1ObjectIdentifier(oid),
                        critical,
                        ASN1Primitive.fromByteArray(derBytes));
            } catch (IOException | IllegalArgumentException e) {
                throw new IllegalArgumentException("Failed to decode extension " + oid, e);
            }
        }
    }

    public record CopyFromCsrSnapshot(String oid, boolean required) {}

    private static String subjectKey(ASN1ObjectIdentifier oid) {
        if (BCStyle.CN.equals(oid)) return "CN";
        if (BCStyle.O.equals(oid)) return "O";
        if (BCStyle.OU.equals(oid)) return "OU";
        if (BCStyle.C.equals(oid)) return "C";
        if (BCStyle.L.equals(oid)) return "L";
        if (BCStyle.ST.equals(oid)) return "ST";
        if (BCStyle.E.equals(oid)) return "E";
        return oid.getId();
    }

    public static ASN1ObjectIdentifier parseSubjectOid(String key) {
        return switch (key) {
            case "CN", "cn", "commonName" -> BCStyle.CN;
            case "O", "o", "organization" -> BCStyle.O;
            case "OU", "ou", "organizationalUnit" -> BCStyle.OU;
            case "C", "c", "country" -> BCStyle.C;
            case "L", "l", "locality" -> BCStyle.L;
            case "ST", "st", "state" -> BCStyle.ST;
            case "E", "e", "emailAddress" -> BCStyle.E;
            default -> new ASN1ObjectIdentifier(key);
        };
    }

    private static String sanKey(int tag) {
        return switch (tag) {
            case GeneralName.dNSName -> "dns";
            case GeneralName.iPAddress -> "ip";
            case GeneralName.rfc822Name -> "email";
            case GeneralName.uniformResourceIdentifier -> "uri";
            case GeneralName.directoryName -> "directoryName";
            case GeneralName.otherName -> "otherName";
            default -> Integer.toString(tag);
        };
    }

    public static int parseSanTag(String key) {
        return switch (key) {
            case "dns", "dNSName" -> GeneralName.dNSName;
            case "ip", "iPAddress" -> GeneralName.iPAddress;
            case "email", "rfc822Name" -> GeneralName.rfc822Name;
            case "uri", "uniformResourceIdentifier" -> GeneralName.uniformResourceIdentifier;
            case "directoryName" -> GeneralName.directoryName;
            case "otherName" -> GeneralName.otherName;
            default -> {
                try {
                    yield Integer.parseInt(key);
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException("unknown SAN type: " + key);
                }
            }
        };
    }

    private static <K, V> Map<K, V> copyMap(Map<K, V> map) {
        return map == null ? Map.of() : Map.copyOf(map);
    }

    private static <T> List<T> copyList(List<T> list) {
        return list == null ? List.of() : List.copyOf(list);
    }

    private static <K, V> Map<K, V> mergeMaps(Map<K, V> base, Map<K, V> overlay) {
        if (overlay == null || overlay.isEmpty()) {
            return base;
        }
        Map<K, V> merged = new LinkedHashMap<>(base);
        merged.putAll(overlay);
        return merged;
    }

    private static <T> List<T> replaceIfNonEmpty(List<T> base, List<T> overlay) {
        if (overlay == null || overlay.isEmpty()) {
            return base;
        }
        return overlay;
    }
}
