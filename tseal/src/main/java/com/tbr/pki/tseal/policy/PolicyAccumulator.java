package com.tbr.pki.tseal.policy;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.KeyPurposeId;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

class PolicyAccumulator {

    final Map<ASN1ObjectIdentifier, FieldRule> subjectRules = new LinkedHashMap<>();
    final Map<Integer, FieldRule> sanTypeRules = new LinkedHashMap<>();
    final Map<ASN1ObjectIdentifier, FieldRule> otherNameRules = new LinkedHashMap<>();

    ValidityRule validity;

    boolean adaptiveKeyUsage;
    Integer keyUsageBits;
    KeyPurposeId[] eku;
    boolean endEntity;
    boolean ca;
    Integer pathLen;
    boolean atLeastOneSan;

    final List<String> crlUris = new ArrayList<>();
    final List<String> ocspUris = new ArrayList<>();
    final List<String> caIssuersUris = new ArrayList<>();

    final List<CaExtension> extraExtensions = new ArrayList<>();
    final Map<ASN1ObjectIdentifier, Boolean> copyFromCsr = new LinkedHashMap<>();
    final Set<ASN1ObjectIdentifier> ignoreCsrExtensions = new LinkedHashSet<>();

    record CaExtension(ASN1ObjectIdentifier oid, boolean critical, ASN1Encodable value) {}

    void requireUri(String uri, String what) {
        if (uri == null || uri.isBlank()) {
            throw new IllegalArgumentException(what + " URI must be non-blank");
        }
    }

    void putSubject(ASN1ObjectIdentifier oid, FieldRule rule) {
        subjectRules.put(oid, requireRule(rule));
    }

    void putSanType(int tag, FieldRule rule) {
        sanTypeRules.put(tag, requireRule(rule));
    }

    void putOtherName(ASN1ObjectIdentifier oid, FieldRule rule) {
        otherNameRules.put(oid, requireRule(rule));
    }

    void setValidity(ValidityRule rule) {
        requireRule(rule).validateStatically();
        this.validity = rule;
    }

    void setValidity(java.time.Duration duration) {
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
