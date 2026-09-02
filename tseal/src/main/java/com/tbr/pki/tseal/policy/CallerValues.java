package com.tbr.pki.tseal.policy;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

public final class CallerValues {

    String commonName;
    String organization;
    String organizationalUnit;
    String country;
    final List<String> dns = new ArrayList<>();
    final List<String> ip = new ArrayList<>();
    final List<String> email = new ArrayList<>();
    Duration validity;

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

    private static String requireText(String value, String what) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(what + " must be non-blank");
        }
        return value;
    }
}
