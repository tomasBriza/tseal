package com.tbr.pki.tseal.policy;

import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

public final class FieldRule {

    enum Mode { FROM_CSR, EXACTLY, FORBIDDEN }

    final Mode mode;
    final boolean optional;
    final boolean orCaller;
    final String exactValue;
    final String defaultValue;
    final Pattern pattern;
    final List<String> oneOf;
    final Integer maxLength;
    final Integer maxEntries;

    private FieldRule(
            Mode mode,
            boolean optional,
            boolean orCaller,
            String exactValue,
            String defaultValue,
            Pattern pattern,
            List<String> oneOf,
            Integer maxLength,
            Integer maxEntries) {
        this.mode = mode;
        this.optional = optional;
        this.orCaller = orCaller;
        this.exactValue = exactValue;
        this.defaultValue = defaultValue;
        this.pattern = pattern;
        this.oneOf = oneOf;
        this.maxLength = maxLength;
        this.maxEntries = maxEntries;
    }

    static FieldRule fromCsrRequired() {
        return new FieldRule(Mode.FROM_CSR, false, false, null, null, null, null, null, null);
    }

    static FieldRule exact(String value) {
        Objects.requireNonNull(value, "exact value");
        if (value.isEmpty()) {
            throw new IllegalArgumentException("exact value must be non-empty");
        }
        return new FieldRule(Mode.EXACTLY, false, false, value, null, null, null, null, null);
    }

    static FieldRule forbid() {
        return new FieldRule(Mode.FORBIDDEN, false, false, null, null, null, null, null, null);
    }

    static FieldRule fromSnapshot(String mode, boolean optional, boolean orCaller, String exact,
                                  String orDefault, String matching, List<String> oneOf,
                                  Integer maxLength, Integer maxEntries) {
        FieldRule rule = switch (parseMode(mode)) {
            case FROM_CSR -> fromCsrRequired();
            case EXACTLY -> exact(exact);
            case FORBIDDEN -> forbid();
        };
        if (optional) {
            rule = rule.optional();
        }
        if (orCaller) {
            rule = rule.orCaller();
        }
        if (orDefault != null) {
            rule = rule.orDefault(orDefault);
        }
        if (matching != null) {
            rule = rule.matching(matching);
        }
        if (oneOf != null && !oneOf.isEmpty()) {
            rule = rule.oneOf(oneOf.toArray(String[]::new));
        }
        if (maxLength != null) {
            rule = rule.maxLength(maxLength);
        }
        if (maxEntries != null) {
            rule = rule.maxEntries(maxEntries);
        }
        return rule;
    }

    static Mode parseMode(String mode) {
        if (mode == null || mode.isBlank()) {
            throw new IllegalArgumentException("field rule mode is required");
        }
        return switch (mode) {
            case "fromCsr", "FROM_CSR" -> Mode.FROM_CSR;
            case "exactly", "EXACTLY" -> Mode.EXACTLY;
            case "forbidden", "FORBIDDEN" -> Mode.FORBIDDEN;
            default -> throw new IllegalArgumentException("unknown field rule mode: " + mode);
        };
    }

    static String modeName(Mode mode) {
        return switch (mode) {
            case FROM_CSR -> "fromCsr";
            case EXACTLY -> "exactly";
            case FORBIDDEN -> "forbidden";
        };
    }

    public FieldRule optional() {
        return copy(mode, true, orCaller, exactValue, defaultValue, pattern, oneOf, maxLength, maxEntries);
    }

    /** Alias of the default {@code fromCsr()} (required). */
    public FieldRule required() {
        return copy(mode, false, orCaller, exactValue, defaultValue, pattern, oneOf, maxLength, maxEntries);
    }

    public FieldRule orCaller() {
        return copy(mode, optional, true, exactValue, defaultValue, pattern, oneOf, maxLength, maxEntries);
    }

    public FieldRule orDefault(String value) {
        Objects.requireNonNull(value, "default value");
        if (value.isEmpty()) {
            throw new IllegalArgumentException("default value must be non-empty");
        }
        return copy(mode, optional, orCaller, exactValue, value, pattern, oneOf, maxLength, maxEntries);
    }

    public FieldRule matching(String regex) {
        Objects.requireNonNull(regex, "regex");
        return copy(mode, optional, orCaller, exactValue, defaultValue, Pattern.compile(regex), oneOf, maxLength, maxEntries);
    }

    public FieldRule oneOf(String... allowed) {
        Objects.requireNonNull(allowed, "allowed");
        if (allowed.length == 0) {
            throw new IllegalArgumentException("oneOf requires at least one value");
        }
        return copy(mode, optional, orCaller, exactValue, defaultValue, pattern, List.of(allowed), maxLength, maxEntries);
    }

    public FieldRule maxLength(int n) {
        if (n < 1) {
            throw new IllegalArgumentException("maxLength must be at least 1");
        }
        return copy(mode, optional, orCaller, exactValue, defaultValue, pattern, oneOf, n, maxEntries);
    }

    public FieldRule maxEntries(int n) {
        if (n < 1) {
            throw new IllegalArgumentException("maxEntries must be at least 1");
        }
        return copy(mode, optional, orCaller, exactValue, defaultValue, pattern, oneOf, maxLength, n);
    }

    boolean constraintOk(String value) {
        if (value == null) {
            return false;
        }
        if (maxLength != null && value.length() > maxLength) {
            return false;
        }
        if (oneOf != null && !oneOf.contains(value)) {
            return false;
        }
        if (pattern != null && !pattern.matcher(value).matches()) {
            return false;
        }
        return true;
    }

    String constraintMessage(String value) {
        if (maxLength != null && value.length() > maxLength) {
            return "exceeds maxLength " + maxLength;
        }
        if (oneOf != null && !oneOf.contains(value)) {
            return "not in whitelist";
        }
        if (pattern != null && !pattern.matcher(value).matches()) {
            return "does not match " + pattern.pattern();
        }
        return "invalid";
    }

    private static FieldRule copy(
            Mode mode,
            boolean optional,
            boolean orCaller,
            String exactValue,
            String defaultValue,
            Pattern pattern,
            List<String> oneOf,
            Integer maxLength,
            Integer maxEntries) {
        return new FieldRule(mode, optional, orCaller, exactValue, defaultValue, pattern, oneOf, maxLength, maxEntries);
    }
}
