package com.tbr.pki.tseal.policy;

public final class Rules {

    private Rules() {}

    public static FieldRule fromCsr() {
        return FieldRule.fromCsrRequired();
    }

    public static FieldRule exactly(String value) {
        return FieldRule.exact(value);
    }

    public static FieldRule forbidden() {
        return FieldRule.forbid();
    }

    /** Ignore the CSR; take caller and/or {@code orDefault}. */
    public static FieldRule ignoreCsr() {
        return FieldRule.ignoreCsrValues();
    }
}
