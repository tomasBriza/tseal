package com.tbr.pki.tseal.policy;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class CallerValues {

    public String commonName;
    public String organization;
    public String organizationalUnit;
    public String country;
    public final List<String> dns = new ArrayList<>();
    public final List<String> ip = new ArrayList<>();
    public final List<String> email = new ArrayList<>();
    public Duration validity;
    public final Map<String, String> attrs = new LinkedHashMap<>();

    private CallerValues() {}

    public static CallerValues empty() {
        return new CallerValues();
    }

    public static CallerValues of() {
        return new CallerValues();
    }

    public CallerValues commonName(String cn) {
        this.commonName = requireText(cn, "commonName");
        return this;
    }

    public CallerValues organization(String o) {
        this.organization = requireText(o, "organization");
        return this;
    }

    public CallerValues organizationalUnit(String ou) {
        this.organizationalUnit = requireText(ou, "organizationalUnit");
        return this;
    }

    public CallerValues country(String c) {
        this.country = requireText(c, "country");
        return this;
    }

    public CallerValues dns(String dnsName) {
        dns.add(requireText(dnsName, "dns"));
        return this;
    }

    public CallerValues ip(String ipAddress) {
        ip.add(requireText(ipAddress, "ip"));
        return this;
    }

    public CallerValues email(String emailAddress) {
        email.add(requireText(emailAddress, "email"));
        return this;
    }

    public CallerValues validity(Duration lifetime) {
        this.validity = ValidityRule.requirePositive(lifetime, "caller");
        return this;
    }

    public CallerValues attr(String name, String value) {
        attrs.put(requireText(name, "attr name"), requireText(value, "attr value"));
        return this;
    }

    public String attr(String name) {
        return attrs.get(name);
    }

    private static String requireText(String value, String what) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(what + " must be non-blank");
        }
        return value;
    }
}
