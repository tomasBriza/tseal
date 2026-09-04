package com.tbr.pki.tseal.policy;

/** Stable machine tokens for {@link PolicyViolation#code()}. */
public final class ViolationCodes {

    public static final String POLICY = "policy.violation";

    public static final String SUBJECT_UNKNOWN = "subject.unknown";
    public static final String SUBJECT_FORBIDDEN = "subject.forbidden";
    public static final String SUBJECT_REQUIRED = "subject.required";
    public static final String SUBJECT_CARDINALITY = "subject.cardinality";

    public static final String SAN_UNKNOWN = "san.unknown";
    public static final String SAN_FORBIDDEN = "san.forbidden";
    public static final String SAN_REQUIRED = "san.required";
    public static final String SAN_CARDINALITY = "san.cardinality";

    public static final String VALUE_REGEX = "value.regex";
    public static final String VALUE_ONE_OF = "value.oneOf";
    public static final String VALUE_MAX_LENGTH = "value.maxLength";
    public static final String VALUE_COUNTRY = "value.country";

    public static final String VALIDITY_FORBIDDEN = "validity.forbidden";
    public static final String VALIDITY_REQUIRED = "validity.required";
    public static final String VALIDITY_RANGE = "validity.range";

    public static final String EXTENSION_UNKNOWN = "extension.unknown";
    public static final String EXTENSION_REQUIRED = "extension.required";
    public static final String EXTENSION = "extension";

    private ViolationCodes() {}
}
