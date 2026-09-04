package com.tbr.pki.tseal.policy.engine;

import com.tbr.pki.tseal.csr.Oids;
import com.tbr.pki.tseal.policy.CallerValues;
import com.tbr.pki.tseal.policy.FieldRule;
import com.tbr.pki.tseal.policy.PolicyViolationException;
import com.tbr.pki.tseal.policy.ValidityRule;
import com.tbr.pki.tseal.policy.ViolationCodes;
import com.tbr.pki.tseal.policy.restriction.RestrictionOutcome;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.OtherName;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.IOException;
import java.security.PublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class PolicyEngine {

    private PolicyEngine() {}

    public static void check(PolicyAccumulator spec, PKCS10CertificationRequest csr, CallerValues caller) {
        Evaluation evaluation = evaluate(spec, csr, caller == null ? CallerValues.empty() : caller);
        if (!evaluation.ok()) {
            throw new PolicyViolationException(evaluation.violations);
        }
    }

    public static Evaluation evaluate(PolicyAccumulator spec, PKCS10CertificationRequest csr, CallerValues caller) {
        CsrView view = CsrView.parse(csr);
        Evaluation out = new Evaluation();
        evaluateSubject(spec, view, caller, out);
        evaluateSan(spec, view, caller, out);
        evaluateValidity(spec, view, caller, out);
        evaluateUnknownExtensions(spec, view, out);
        copyRequiredExtensions(spec, view, out);
        materializeCaExtensions(spec, view, out);
        return out;
    }

    private static void evaluateSubject(
            PolicyAccumulator spec, CsrView view, CallerValues caller, Evaluation out) {
        X500NameBuilder names = new X500NameBuilder(BCStyle.INSTANCE);
        for (var entry : spec.subjectRules.entrySet()) {
            ASN1ObjectIdentifier oid = entry.getKey();
            FieldRule rule = entry.getValue();
            String field = subjectField(oid);
            List<String> csrValues = view.subject.getOrDefault(oid, List.of());
            String callerValue = callerSubject(oid, caller);
            List<String> callerValues = callerValue == null ? List.of() : List.of(callerValue);
            List<String> winning = resolveList(rule, csrValues, callerValues, field, true, out);
            boolean country = BCStyle.C.equals(oid);
            for (String value : winning) {
                if (country) {
                    names.addRDN(oid, new DERPrintableString(value));
                } else {
                    names.addRDN(oid, value);
                }
            }
        }
        for (ASN1ObjectIdentifier oid : view.subject.keySet()) {
            if (!spec.subjectRules.containsKey(oid)) {
                out.add("unknown.subject." + oid.getId(),
                        "subject RDN is not allowed by the policy",
                        ViolationCodes.SUBJECT_UNKNOWN);
            }
        }
        out.subject = names.build();
    }

    private static String callerSubject(ASN1ObjectIdentifier oid, CallerValues caller) {
        if (BCStyle.CN.equals(oid)) return caller.commonName;
        if (BCStyle.O.equals(oid)) return caller.organization;
        if (BCStyle.OU.equals(oid)) return caller.organizationalUnit;
        if (BCStyle.C.equals(oid)) return caller.country;
        return null;
    }

    private static String subjectField(ASN1ObjectIdentifier oid) {
        if (BCStyle.CN.equals(oid)) return "subject.CN";
        if (BCStyle.O.equals(oid)) return "subject.O";
        if (BCStyle.OU.equals(oid)) return "subject.OU";
        if (BCStyle.C.equals(oid)) return "subject.C";
        if (BCStyle.E.equals(oid)) return "subject.E";
        return "subject." + oid.getId();
    }

    private static void evaluateSan(
            PolicyAccumulator spec, CsrView view, CallerValues caller, Evaluation out) {
        List<GeneralName> san = new ArrayList<>();
        addSanStrings(spec, GeneralName.dNSName, "san.dNSName", view.dns, caller.dns, san, out);
        addSanStrings(spec, GeneralName.iPAddress, "san.iPAddress", view.ip, caller.ip, san, out);
        addSanStrings(spec, GeneralName.rfc822Name, "san.rfc822Name", view.email, caller.email, san, out);
        evaluateOtherNames(spec, view, san, out);

        for (var tagCount : view.sanTagCounts.entrySet()) {
            int tag = tagCount.getKey();
            if (tag == GeneralName.otherName) {
                continue;
            }
            if (!spec.sanTypeRules.containsKey(tag)) {
                out.add("unknown.san." + sanTagName(tag),
                        "SAN type is not allowed by the policy",
                        ViolationCodes.SAN_UNKNOWN);
            }
        }
        if (!view.otherNames.isEmpty()
                && spec.otherNameRules.isEmpty()
                && !spec.sanTypeRules.containsKey(GeneralName.otherName)) {
            out.add("unknown.san.otherName",
                    "SAN type is not allowed by the policy",
                    ViolationCodes.SAN_UNKNOWN);
        } else {
            for (ASN1ObjectIdentifier oid : view.otherNames.keySet()) {
                if (!spec.otherNameRules.containsKey(oid)
                        && !spec.sanTypeRules.containsKey(GeneralName.otherName)) {
                    out.add("unknown.san.otherName." + oid.getId(),
                            "otherName is not allowed by the policy",
                            ViolationCodes.SAN_UNKNOWN);
                }
            }
        }

        if (spec.atLeastOneSan) {
            boolean produced = san.stream().anyMatch(n ->
                    n.getTagNo() == GeneralName.dNSName || n.getTagNo() == GeneralName.iPAddress);
            if (!produced) {
                out.add("san", "at least one SAN (dns or ip) is required", ViolationCodes.SAN_REQUIRED);
            }
        }
        out.san.addAll(san);
    }

    private static void addSanStrings(
            PolicyAccumulator spec,
            int tag,
            String field,
            List<String> csrValues,
            List<String> callerValues,
            List<GeneralName> san,
            Evaluation out) {
        FieldRule rule = spec.sanTypeRules.get(tag);
        if (rule == null) {
            return;
        }
        List<String> winning = resolveList(rule, csrValues, callerValues, field, false, out);
        for (String value : winning) {
            san.add(new GeneralName(tag, value));
        }
    }

    private static void evaluateOtherNames(
            PolicyAccumulator spec, CsrView view, List<GeneralName> san, Evaluation out) {
        FieldRule generic = spec.sanTypeRules.get(GeneralName.otherName);
        for (var entry : spec.otherNameRules.entrySet()) {
            ASN1ObjectIdentifier oid = entry.getKey();
            FieldRule rule = entry.getValue();
            List<String> csrValues = view.otherNames.getOrDefault(oid, List.of());
            List<String> winning = resolveList(rule, csrValues, List.of(), "san.otherName." + oid.getId(), false, out);
            for (String value : winning) {
                san.add(new GeneralName(GeneralName.otherName, new OtherName(oid, new DERUTF8String(value))));
            }
        }
        if (generic != null) {
            List<String> all = new ArrayList<>();
            for (List<String> values : view.otherNames.values()) {
                all.addAll(values);
            }
            resolveList(generic, all, List.of(), "san.otherName", false, out);
        }
    }

    private static void evaluateValidity(
            PolicyAccumulator spec, CsrView view, CallerValues caller, Evaluation out) {
        ValidityRule rule = spec.validity;
        Duration csrValue = view.requestedValidity;
        Duration callerValue = caller.validity;
        Duration winning = switch (rule.mode) {
            case EXACTLY -> rule.exactValue;
            case FORBIDDEN -> {
                if (csrValue != null) {
                    out.add("validity", "requested validity is forbidden", ViolationCodes.VALIDITY_FORBIDDEN);
                }
                if (rule.orCaller && callerValue != null) {
                    yield callerValue;
                }
                yield rule.defaultValue;
            }
            case FROM_CSR -> {
                if (csrValue != null) {
                    if (csrValue.toSeconds() <= 0 || !rule.inRange(csrValue)) {
                        out.add("validity", csrValue.toSeconds() <= 0
                                ? "requested validity must be at least one second"
                                : rule.rangeMessage(csrValue),
                                ViolationCodes.VALIDITY_RANGE);
                        yield null;
                    }
                    yield csrValue;
                }
                if (rule.orCaller && callerValue != null) {
                    yield callerValue;
                }
                if (rule.defaultValue != null) {
                    yield rule.defaultValue;
                }
                if (!rule.optional) {
                    out.add("validity", "required requested validity is missing", ViolationCodes.VALIDITY_REQUIRED);
                } else if (!rule.orCaller) {
                    out.add("validity", "validity is missing", ViolationCodes.VALIDITY_REQUIRED);
                } else {
                    out.add("validity", "required validity is missing from CSR and caller",
                            ViolationCodes.VALIDITY_REQUIRED);
                }
                yield null;
            }
        };
        if (winning != null && !rule.inRange(winning)) {
            out.add("validity", rule.rangeMessage(winning), ViolationCodes.VALIDITY_RANGE);
            winning = null;
        }
        out.validity = winning;
    }

    private static void evaluateUnknownExtensions(PolicyAccumulator spec, CsrView view, Evaluation out) {
        Set<ASN1ObjectIdentifier> owned = ownedOids(spec);
        for (ASN1ObjectIdentifier oid : view.requestedExtensions.keySet()) {
            if (owned.contains(oid) || spec.ignoreCsrExtensions.contains(oid) || spec.copyFromCsr.containsKey(oid)) {
                continue;
            }
            out.add("extension.request." + oid.getId(),
                    "extension is not allowed by the policy",
                    ViolationCodes.EXTENSION_UNKNOWN);
        }
    }

    private static void copyRequiredExtensions(PolicyAccumulator spec, CsrView view, Evaluation out) {
        for (var entry : spec.copyFromCsr.entrySet()) {
            ASN1ObjectIdentifier oid = entry.getKey();
            boolean required = entry.getValue();
            if (!view.requestedExtensions.containsKey(oid) && required) {
                out.add("extension.request." + oid.getId(),
                        "required CSR extension is missing",
                        ViolationCodes.EXTENSION_REQUIRED);
            }
        }
    }

    private static void materializeCaExtensions(PolicyAccumulator spec, CsrView view, Evaluation out) {
        try {
            ExtensionsGenerator gen = new ExtensionsGenerator();
            Integer ku = keyUsageBits(spec, view.publicKey);
            out.keyUsageBits = ku;
            if (ku != null) {
                gen.addExtension(Extension.keyUsage, true, new KeyUsage(ku));
            }
            if (spec.eku != null && spec.eku.length > 0) {
                gen.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(spec.eku));
            }
            if (spec.endEntity) {
                gen.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            } else if (spec.ca) {
                BasicConstraints bc = spec.pathLen == null
                        ? new BasicConstraints(true)
                        : new BasicConstraints(spec.pathLen);
                gen.addExtension(Extension.basicConstraints, true, bc);
            }
            if (!out.san.isEmpty()) {
                gen.addExtension(Extension.subjectAlternativeName, false,
                        new GeneralNames(out.san.toArray(new GeneralName[0])));
            }
            addCrl(spec, gen);
            addAia(spec, gen);
            for (var extra : spec.extraExtensions) {
                gen.addExtension(extra.oid(), extra.critical(), extra.value());
            }
            for (var entry : spec.copyFromCsr.entrySet()) {
                var ext = view.requestedExtensions.get(entry.getKey());
                if (ext != null) {
                    gen.addExtension(ext);
                }
            }
            if (!gen.isEmpty()) {
                out.extensions = gen.generate();
            }
        } catch (IOException e) {
            out.add("extension", "failed to materialize CA extensions: " + e.getMessage(),
                    ViolationCodes.EXTENSION);
        }
    }

    private static void addCrl(PolicyAccumulator spec, ExtensionsGenerator gen) throws IOException {
        if (spec.crlUris.isEmpty()) {
            return;
        }
        DistributionPoint[] points = spec.crlUris.stream()
                .map(uri -> new DistributionPoint(
                        new DistributionPointName(new GeneralNames(
                                new GeneralName(GeneralName.uniformResourceIdentifier, uri))),
                        null, null))
                .toArray(DistributionPoint[]::new);
        gen.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(points));
    }

    private static void addAia(PolicyAccumulator spec, ExtensionsGenerator gen) throws IOException {
        if (spec.ocspUris.isEmpty() && spec.caIssuersUris.isEmpty()) {
            return;
        }
        List<AccessDescription> descriptions = new ArrayList<>();
        for (String uri : spec.ocspUris) {
            descriptions.add(new AccessDescription(
                    AccessDescription.id_ad_ocsp,
                    new GeneralName(GeneralName.uniformResourceIdentifier, uri)));
        }
        for (String uri : spec.caIssuersUris) {
            descriptions.add(new AccessDescription(
                    AccessDescription.id_ad_caIssuers,
                    new GeneralName(GeneralName.uniformResourceIdentifier, uri)));
        }
        gen.addExtension(Extension.authorityInfoAccess, false,
                new AuthorityInformationAccess(descriptions.toArray(AccessDescription[]::new)));
    }

    private static Integer keyUsageBits(PolicyAccumulator spec, PublicKey publicKey) {
        if (spec.adaptiveKeyUsage) {
            boolean rsa = publicKey != null && "RSA".equals(publicKey.getAlgorithm());
            return rsa
                    ? KeyUsage.digitalSignature | KeyUsage.keyEncipherment
                    : KeyUsage.digitalSignature;
        }
        return spec.keyUsageBits;
    }

    private static Set<ASN1ObjectIdentifier> ownedOids(PolicyAccumulator spec) {
        Set<ASN1ObjectIdentifier> owned = new LinkedHashSet<>();
        owned.add(Extension.keyUsage);
        owned.add(Extension.extendedKeyUsage);
        owned.add(Extension.basicConstraints);
        owned.add(Extension.subjectAlternativeName);
        owned.add(Oids.REQUESTED_VALIDITY);
        if (!spec.crlUris.isEmpty()) {
            owned.add(Extension.cRLDistributionPoints);
        }
        if (!spec.ocspUris.isEmpty() || !spec.caIssuersUris.isEmpty()) {
            owned.add(Extension.authorityInfoAccess);
        }
        for (var extra : spec.extraExtensions) {
            owned.add(extra.oid());
        }
        return owned;
    }

    public static List<String> resolveList(
            FieldRule rule,
            List<String> csrValues,
            List<String> callerValues,
            String field,
            boolean subject,
            Evaluation out) {
        String forbiddenCode = subject ? ViolationCodes.SUBJECT_FORBIDDEN : ViolationCodes.SAN_FORBIDDEN;
        String requiredCode = subject ? ViolationCodes.SUBJECT_REQUIRED : ViolationCodes.SAN_REQUIRED;
        String cardinalityCode = subject ? ViolationCodes.SUBJECT_CARDINALITY : ViolationCodes.SAN_CARDINALITY;

        if (rule.mode == FieldRule.Mode.EXACTLY) {
            String value = constrain(rule, rule.exactValue, field, out);
            return value == null ? List.of() : List.of(value);
        }
        if (rule.mode == FieldRule.Mode.FORBIDDEN) {
            if (csrValues != null && !csrValues.isEmpty()) {
                out.add(field, "value is forbidden", forbiddenCode);
            }
            return List.of();
        }
        List<String> union = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        boolean ignoreCsr = rule.mode == FieldRule.Mode.IGNORE_CSR;
        if (!ignoreCsr && csrValues != null) {
            for (String v : csrValues) {
                if (seen.add(v)) {
                    union.add(v);
                }
            }
        }
        if (rule.orCaller && callerValues != null) {
            for (String v : callerValues) {
                if (seen.add(v)) {
                    union.add(v);
                }
            }
        }
        if (union.isEmpty()) {
            if (rule.defaultValue != null) {
                union.add(rule.defaultValue);
            } else if (!rule.optional) {
                out.add(field, "required value is missing", requiredCode);
                return List.of();
            } else {
                return List.of();
            }
        }
        int min = rule.minEntries != null ? rule.minEntries : (rule.optional ? 0 : 1);
        int max;
        if (rule.maxEntries != null) {
            max = rule.maxEntries;
        } else {
            max = subject ? 1 : Integer.MAX_VALUE;
        }
        if (union.size() < min || union.size() > max) {
            out.add(field, "expected between " + min + " and " + (max == Integer.MAX_VALUE ? "unlimited" : max)
                    + " entries, got " + union.size(), cardinalityCode);
            return List.of();
        }
        List<String> ok = new ArrayList<>();
        for (String value : union) {
            String constrained = constrain(rule, value, field, out);
            if (constrained != null) {
                ok.add(constrained);
            }
        }
        return ok;
    }

    private static String constrain(FieldRule rule, String value, String field, Evaluation out) {
        if (value == null) {
            return null;
        }
        return switch (rule.evaluateRestrictions(value)) {
            case RestrictionOutcome.Allow() -> value;
            case RestrictionOutcome.Reject(var code, var message) -> {
                out.add(field, message, code);
                yield null;
            }
        };
    }

    private static String sanTagName(int tag) {
        return switch (tag) {
            case GeneralName.otherName -> "otherName";
            case GeneralName.rfc822Name -> "rfc822Name";
            case GeneralName.dNSName -> "dNSName";
            case GeneralName.uniformResourceIdentifier -> "uniformResourceIdentifier";
            case GeneralName.iPAddress -> "iPAddress";
            case GeneralName.directoryName -> "directoryName";
            default -> Integer.toString(tag);
        };
    }
}
