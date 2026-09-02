package com.tbr.pki.tseal.policy;

import com.tbr.pki.tseal.csr.Oids;
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
import java.util.regex.Pattern;

class PolicyEngine {

    private static final Pattern COUNTRY = Pattern.compile("[A-Z]{2}");

    private PolicyEngine() {}

    static void check(PolicyAccumulator spec, PKCS10CertificationRequest csr, CallerValues caller) {
        Evaluation evaluation = evaluate(spec, csr, caller == null ? CallerValues.empty() : caller);
        if (!evaluation.ok()) {
            throw new PolicyViolationException(evaluation.violations);
        }
    }

    static Evaluation evaluate(PolicyAccumulator spec, PKCS10CertificationRequest csr, CallerValues caller) {
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
            String csrValue = view.subject.get(oid);
            if (view.duplicateSubject.contains(oid)) {
                out.add(field, "multiple values in CSR");
            }
            String callerValue = callerSubject(oid, caller);
            boolean country = BCStyle.C.equals(oid);
            String winning = resolveSingle(rule, csrValue, callerValue, field, country, out);
            if (winning != null) {
                if (country) {
                    names.addRDN(oid, new DERPrintableString(winning));
                } else {
                    names.addRDN(oid, winning);
                }
            }
        }
        for (ASN1ObjectIdentifier oid : view.subject.keySet()) {
            if (!spec.subjectRules.containsKey(oid)) {
                out.add("unknown.subject." + oid.getId(), "subject RDN is not allowed by the policy");
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
                out.add("unknown.san." + sanTagName(tag), "SAN type is not allowed by the policy");
            }
        }
        if (!view.otherNames.isEmpty()
                && spec.otherNameRules.isEmpty()
                && !spec.sanTypeRules.containsKey(GeneralName.otherName)) {
            out.add("unknown.san.otherName", "SAN type is not allowed by the policy");
        } else {
            for (ASN1ObjectIdentifier oid : view.otherNames.keySet()) {
                if (!spec.otherNameRules.containsKey(oid)
                        && !spec.sanTypeRules.containsKey(GeneralName.otherName)) {
                    out.add("unknown.san.otherName." + oid.getId(), "otherName is not allowed by the policy");
                }
            }
        }

        if (spec.atLeastOneSan) {
            boolean produced = san.stream().anyMatch(n ->
                    n.getTagNo() == GeneralName.dNSName || n.getTagNo() == GeneralName.iPAddress);
            if (!produced) {
                out.add("san", "at least one SAN (dns or ip) is required");
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
        List<String> winning = resolveList(rule, csrValues, callerValues, field, out);
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
            List<String> winning = resolveList(rule, csrValues, List.of(), "san.otherName." + oid.getId(), out);
            for (String value : winning) {
                san.add(new GeneralName(GeneralName.otherName, new OtherName(oid, new DERUTF8String(value))));
            }
        }
        if (generic != null) {
            List<String> all = new ArrayList<>();
            for (List<String> values : view.otherNames.values()) {
                all.addAll(values);
            }
            resolveList(generic, all, List.of(), "san.otherName", out);
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
                    out.add("validity", "requested validity is forbidden");
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
                                : rule.rangeMessage(csrValue));
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
                    out.add("validity", "required requested validity is missing");
                } else if (!rule.orCaller) {
                    out.add("validity", "validity is missing");
                } else {
                    out.add("validity", "required validity is missing from CSR and caller");
                }
                yield null;
            }
        };
        if (winning != null && !rule.inRange(winning)) {
            out.add("validity", rule.rangeMessage(winning));
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
            out.add("extension.request." + oid.getId(), "extension is not allowed by the policy");
        }
    }

    private static void copyRequiredExtensions(PolicyAccumulator spec, CsrView view, Evaluation out) {
        for (var entry : spec.copyFromCsr.entrySet()) {
            ASN1ObjectIdentifier oid = entry.getKey();
            boolean required = entry.getValue();
            if (!view.requestedExtensions.containsKey(oid) && required) {
                out.add("extension.request." + oid.getId(), "required CSR extension is missing");
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
            out.add("extension", "failed to materialize CA extensions: " + e.getMessage());
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

    static String resolveSingle(
            FieldRule rule, String csrValue, String callerValue, String field, boolean country, Evaluation out) {
        return switch (rule.mode) {
            case EXACTLY -> constrain(rule, rule.exactValue, field, country, out);
            case FORBIDDEN -> {
                if (csrValue != null) {
                    out.add(field, "value is forbidden");
                }
                yield null;
            }
            case FROM_CSR -> {
                if (csrValue != null) {
                    yield constrain(rule, csrValue, field, country, out);
                }
                if (rule.orCaller && callerValue != null) {
                    yield constrain(rule, callerValue, field, country, out);
                }
                if (rule.defaultValue != null) {
                    yield constrain(rule, rule.defaultValue, field, country, out);
                }
                if (!rule.optional) {
                    out.add(field, "required value is missing");
                }
                yield null;
            }
        };
    }

    static List<String> resolveList(
            FieldRule rule, List<String> csrValues, List<String> callerValues, String field, Evaluation out) {
        if (rule.mode == FieldRule.Mode.EXACTLY) {
            String value = constrain(rule, rule.exactValue, field, false, out);
            return value == null ? List.of() : List.of(value);
        }
        if (rule.mode == FieldRule.Mode.FORBIDDEN) {
            if (csrValues != null && !csrValues.isEmpty()) {
                out.add(field, "value is forbidden");
            }
            return List.of();
        }
        List<String> union = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        if (csrValues != null) {
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
                out.add(field, "required value is missing");
                return List.of();
            } else {
                return List.of();
            }
        }
        if (rule.maxEntries != null && union.size() > rule.maxEntries) {
            out.add(field, "exceeds maxEntries " + rule.maxEntries);
            return List.of();
        }
        List<String> ok = new ArrayList<>();
        for (String value : union) {
            String constrained = constrain(rule, value, field, false, out);
            if (constrained != null) {
                ok.add(constrained);
            }
        }
        return ok;
    }

    private static String constrain(
            FieldRule rule, String value, String field, boolean country, Evaluation out) {
        if (value == null) {
            return null;
        }
        if (country && rule.pattern == null && rule.oneOf == null && !COUNTRY.matcher(value).matches()) {
            out.add(field, "must be a two-letter ISO country code");
            return null;
        }
        if (!rule.constraintOk(value)) {
            out.add(field, rule.constraintMessage(value));
            return null;
        }
        return value;
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
