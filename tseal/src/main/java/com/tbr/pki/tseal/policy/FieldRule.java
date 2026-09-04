package com.tbr.pki.tseal.policy;

import com.tbr.pki.tseal.policy.restriction.NamedRestriction;
import com.tbr.pki.tseal.policy.restriction.RestrictionOutcome;
import com.tbr.pki.tseal.policy.restriction.RestrictionRule;
import com.tbr.pki.tseal.policy.restriction.RestrictionRules;
import com.tbr.pki.tseal.policy.restriction.RestrictionSnapshot;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public final class FieldRule {

    public enum Mode { FROM_CSR, EXACTLY, FORBIDDEN, IGNORE_CSR }

    public final Mode mode;
    public final boolean optional;
    public final boolean orCaller;
    public final String exactValue;
    public final String defaultValue;
    public final List<NamedRestriction> restrictions;
    public final Integer minEntries;
    public final Integer maxEntries;

    private FieldRule(
            Mode mode,
            boolean optional,
            boolean orCaller,
            String exactValue,
            String defaultValue,
            List<NamedRestriction> restrictions,
            Integer minEntries,
            Integer maxEntries) {
        this.mode = mode;
        this.optional = optional;
        this.orCaller = orCaller;
        this.exactValue = exactValue;
        this.defaultValue = defaultValue;
        this.restrictions = List.copyOf(restrictions);
        this.minEntries = minEntries;
        this.maxEntries = maxEntries;
        if (optional && minEntries != null) {
            throw new IllegalArgumentException("minEntries cannot be combined with optional()");
        }
        if (minEntries != null && minEntries < 1) {
            throw new IllegalArgumentException("minEntries must be at least 1");
        }
        if (maxEntries != null && maxEntries < 1) {
            throw new IllegalArgumentException("maxEntries must be at least 1");
        }
        if (minEntries != null && maxEntries != null && minEntries > maxEntries) {
            throw new IllegalArgumentException("minEntries must be <= maxEntries");
        }
    }

    public static FieldRule fromCsrRequired() {
        return new FieldRule(Mode.FROM_CSR, false, false, null, null, List.of(), null, null);
    }

    public static FieldRule exact(String value) {
        Objects.requireNonNull(value, "exact value");
        if (value.isEmpty()) {
            throw new IllegalArgumentException("exact value must be non-empty");
        }
        return new FieldRule(Mode.EXACTLY, false, false, value, null, List.of(), null, null);
    }

    public static FieldRule forbid() {
        return new FieldRule(Mode.FORBIDDEN, false, false, null, null, List.of(), null, null);
    }

    public static FieldRule ignoreCsrValues() {
        return new FieldRule(Mode.IGNORE_CSR, false, false, null, null, List.of(), null, null);
    }

    public static FieldRule fromSnapshot(
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
            List<RestrictionSnapshot> restrictionSnapshots) {
        FieldRule rule = switch (parseMode(mode)) {
            case FROM_CSR -> fromCsrRequired();
            case EXACTLY -> exact(exact);
            case FORBIDDEN -> forbid();
            case IGNORE_CSR -> ignoreCsrValues();
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
        if (restrictionSnapshots != null && !restrictionSnapshots.isEmpty()) {
            for (RestrictionSnapshot snap : restrictionSnapshots) {
                rule = rule.restrict(snap.toRule());
            }
        } else {
            if (matching != null) {
                rule = rule.matching(matching);
            }
            if (oneOf != null && !oneOf.isEmpty()) {
                rule = rule.oneOf(oneOf.toArray(String[]::new));
            }
            if (maxLength != null) {
                rule = rule.maxLength(maxLength);
            }
        }
        if (minEntries != null) {
            rule = rule.minEntries(minEntries);
        }
        if (maxEntries != null) {
            rule = rule.maxEntries(maxEntries);
        }
        return rule;
    }

    public static Mode parseMode(String mode) {
        if (mode == null || mode.isBlank()) {
            throw new IllegalArgumentException("field rule mode is required");
        }
        return switch (mode) {
            case "fromCsr", "FROM_CSR" -> Mode.FROM_CSR;
            case "exactly", "EXACTLY" -> Mode.EXACTLY;
            case "forbidden", "FORBIDDEN" -> Mode.FORBIDDEN;
            case "ignoreCsr", "IGNORE_CSR" -> Mode.IGNORE_CSR;
            default -> throw new IllegalArgumentException("unknown field rule mode: " + mode);
        };
    }

    public static String modeName(Mode mode) {
        return switch (mode) {
            case FROM_CSR -> "fromCsr";
            case EXACTLY -> "exactly";
            case FORBIDDEN -> "forbidden";
            case IGNORE_CSR -> "ignoreCsr";
        };
    }

    public FieldRule optional() {
        return copy(mode, true, orCaller, exactValue, defaultValue, restrictions, minEntries, maxEntries);
    }

    /** Alias of the default {@code fromCsr()} (required). */
    public FieldRule required() {
        return copy(mode, false, orCaller, exactValue, defaultValue, restrictions, minEntries, maxEntries);
    }

    public FieldRule orCaller() {
        return copy(mode, optional, true, exactValue, defaultValue, restrictions, minEntries, maxEntries);
    }

    public FieldRule orDefault(String value) {
        Objects.requireNonNull(value, "default value");
        if (value.isEmpty()) {
            throw new IllegalArgumentException("default value must be non-empty");
        }
        return copy(mode, optional, orCaller, exactValue, value, restrictions, minEntries, maxEntries);
    }

    public FieldRule matching(String regex) {
        Objects.requireNonNull(regex, "regex");
        return restrict(RestrictionRules.create("regex", Map.of("pattern", regex)));
    }

    public FieldRule oneOf(String... allowed) {
        Objects.requireNonNull(allowed, "allowed");
        if (allowed.length == 0) {
            throw new IllegalArgumentException("oneOf requires at least one value");
        }
        return restrict(RestrictionRules.create("oneOf", Map.of(), List.of(allowed)));
    }

    public FieldRule maxLength(int n) {
        if (n < 1) {
            throw new IllegalArgumentException("maxLength must be at least 1");
        }
        return restrict(RestrictionRules.create("maxLength", Map.of("max", Integer.toString(n))));
    }

    public FieldRule restrict(RestrictionRule rule) {
        Objects.requireNonNull(rule, "restriction");
        List<NamedRestriction> next = new ArrayList<>(restrictions);
        next.add(wrap(rule));
        return copy(mode, optional, orCaller, exactValue, defaultValue, next, minEntries, maxEntries);
    }

    /** Uses a type previously bound with {@link RestrictionRules#bind(String, RestrictionRule)}. */
    public FieldRule restrict(String type) {
        return restrict(RestrictionRules.create(type, Map.of()));
    }

    public FieldRule restrict(String type, Map<String, String> params) {
        return restrict(RestrictionRules.create(type, params));
    }

    public FieldRule minEntries(int n) {
        return copy(mode, optional, orCaller, exactValue, defaultValue, restrictions, n, maxEntries);
    }

    public FieldRule maxEntries(int n) {
        return copy(mode, optional, orCaller, exactValue, defaultValue, restrictions, minEntries, n);
    }

    public FieldRule withCountryIfNeeded() {
        for (NamedRestriction restriction : restrictions) {
            if ("country".equals(restriction.type) || "regex".equals(restriction.type) || "oneOf".equals(restriction.type)) {
                return this;
            }
        }
        return restrict(RestrictionRules.create("country", Map.of()));
    }

    public boolean hasAnonymousRestriction() {
        return restrictions.stream().anyMatch(NamedRestriction::isUnnamed);
    }

    public RestrictionOutcome evaluateRestrictions(String value) {
        for (NamedRestriction restriction : restrictions) {
            RestrictionOutcome outcome = restriction.evaluate(value);
            if (outcome instanceof RestrictionOutcome.Reject) {
                return outcome;
            }
        }
        return RestrictionOutcome.allow();
    }

    private static NamedRestriction wrap(RestrictionRule rule) {
        if (rule instanceof NamedRestriction named) {
            return named;
        }
        return NamedRestriction.unnamed(rule);
    }

    private static FieldRule copy(
            Mode mode,
            boolean optional,
            boolean orCaller,
            String exactValue,
            String defaultValue,
            List<NamedRestriction> restrictions,
            Integer minEntries,
            Integer maxEntries) {
        return new FieldRule(mode, optional, orCaller, exactValue, defaultValue, restrictions, minEntries, maxEntries);
    }
}
