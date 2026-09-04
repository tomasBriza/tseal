package com.tbr.pki.tseal.policy.engine;

import com.tbr.pki.tseal.policy.FieldRule;
import com.tbr.pki.tseal.policy.ValidityRule;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.KeyPurposeId;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class PolicyAccumulator {

    public final Map<ASN1ObjectIdentifier, FieldRule> subjectRules = new LinkedHashMap<>();
    public final Map<Integer, FieldRule> sanTypeRules = new LinkedHashMap<>();
    public final Map<ASN1ObjectIdentifier, FieldRule> otherNameRules = new LinkedHashMap<>();

    public ValidityRule validity;

    public boolean adaptiveKeyUsage;
    public Integer keyUsageBits;
    public KeyPurposeId[] eku;
    public boolean endEntity;
    public boolean ca;
    public Integer pathLen;
    public boolean atLeastOneSan;

    public final List<String> crlUris = new ArrayList<>();
    public final List<String> ocspUris = new ArrayList<>();
    public final List<String> caIssuersUris = new ArrayList<>();

    public final List<CaExtension> extraExtensions = new ArrayList<>();
    public final Map<ASN1ObjectIdentifier, Boolean> copyFromCsr = new LinkedHashMap<>();
    public final Set<ASN1ObjectIdentifier> ignoreCsrExtensions = new LinkedHashSet<>();

    public record CaExtension(ASN1ObjectIdentifier oid, boolean critical, ASN1Encodable value) {}

    public void requireUri(String uri, String what) {
        if (uri == null || uri.isBlank()) {
            throw new IllegalArgumentException(what + " URI must be non-blank");
        }
    }

    public void putSubject(ASN1ObjectIdentifier oid, FieldRule rule) {
        subjectRules.put(oid, requireRule(rule));
    }

    public void putSanType(int tag, FieldRule rule) {
        sanTypeRules.put(tag, requireRule(rule));
    }

    public void putOtherName(ASN1ObjectIdentifier oid, FieldRule rule) {
        otherNameRules.put(oid, requireRule(rule));
    }

    public void setValidity(ValidityRule rule) {
        requireRule(rule).validateStatically();
        this.validity = rule;
    }

    public void setValidity(java.time.Duration duration) {
        setValidity(ValidityRule.exactly(duration));
    }

    private static FieldRule requireRule(FieldRule rule) {
        if (rule == null) {
            throw new IllegalArgumentException("rule must be non-null");
        }
        return rule;
    }

    private static ValidityRule requireRule(ValidityRule rule) {
        if (rule == null) {
            throw new IllegalArgumentException("rule must be non-null");
        }
        return rule;
    }
}
