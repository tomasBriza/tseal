package com.tbr.pki.tseal.policy.restriction;

import com.tbr.pki.tseal.policy.FieldRule;
import com.tbr.pki.tseal.policy.ViolationCodes;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/**
 * Named restriction types for JSON and {@link FieldRule#restrict(String)}.
 *
 * <pre>{@code
 * @Bean
 * RestrictionRules restrictionRules(AcmeDnsChecker checker) {
 *     return RestrictionRules.builtin()
 *             .bind("acmeDns", checker::isAllowed, "value.acmeDns", "DNS not allowed");
 * }
 * }</pre>
 *
 * <p>{@link #bind bind} is enough: it registers immediately. {@code checker::isAllowed}
 * may be {@code boolean isAllowed(String)} or {@code RestrictionOutcome evaluate(String)}.
 */
public final class RestrictionRules {

    private static final Set<String> BUILT_INS = Set.of("regex", "oneOf", "maxLength", "country");
    private static final AtomicReference<RestrictionRules> CURRENT =
            new AtomicReference<>(new RestrictionRules().withBuiltins());

    private final Map<String, BiFunction<Map<String, String>, List<String>, RestrictionRule>> factories =
            new ConcurrentHashMap<>();

    private RestrictionRules() {}

    public static RestrictionRules current() {
        return CURRENT.get();
    }

    /** The process registry, already containing built-in types. {@link #bind bind} takes effect immediately. */
    public static RestrictionRules builtin() {
        return CURRENT.get();
    }

    /** Test helper: drop custom bindings and restore built-ins. */
    public static RestrictionRules reset() {
        RestrictionRules fresh = new RestrictionRules().withBuiltins();
        CURRENT.set(fresh);
        return fresh;
    }

    /**
     * Bind a JSON type name to a Spring bean / lambda that returns
     * {@link RestrictionOutcome}.
     */
    public RestrictionRules bind(String type, RestrictionRule rule) {
        RestrictionRule delegate = Objects.requireNonNull(rule, "rule");
        return bindFactory(type, (params, values) -> delegate);
    }

    /**
     * Bind a JSON type name to a {@code boolean isAllowed(String)} bean method.
     * Failure code is {@code value.<type>}.
     */
    public RestrictionRules bind(String type, Predicate<String> allowed) {
        return bind(type, allowed, "value." + type, "rejected by " + type);
    }

    /** Same as {@link #bind(String, Predicate)} with an explicit violation code and message. */
    public RestrictionRules bind(String type, Predicate<String> allowed, String code, String message) {
        Objects.requireNonNull(allowed, "allowed");
        Objects.requireNonNull(code, "code");
        Objects.requireNonNull(message, "message");
        return bind(type, (RestrictionRule) value -> allowed.test(value)
                ? RestrictionOutcome.allow()
                : RestrictionOutcome.reject(code, message));
    }

    /** Bind a factory that sees JSON {@code params} (and {@code values} for {@code oneOf}). */
    public RestrictionRules bindFactory(
            String type, BiFunction<Map<String, String>, List<String>, RestrictionRule> factory) {
        requireType(type);
        if (BUILT_INS.contains(type)) {
            throw new IllegalArgumentException("cannot replace built-in restriction type: " + type);
        }
        factories.put(type, Objects.requireNonNull(factory, "factory"));
        return this;
    }

    public RestrictionRules bindFactory(String type, Function<Map<String, String>, RestrictionRule> factory) {
        Objects.requireNonNull(factory, "factory");
        return bindFactory(type, (params, values) -> factory.apply(params == null ? Map.of() : params));
    }

    public RestrictionRule resolve(String type, Map<String, String> parameters) {
        return resolve(type, parameters, List.of());
    }

    public RestrictionRule resolve(String type, Map<String, String> parameters, List<String> values) {
        requireType(type);
        var factory = factories.get(type);
        if (factory == null) {
            throw new IllegalArgumentException("unknown restriction type: " + type);
        }
        Map<String, String> params = parameters == null ? Map.of() : parameters;
        List<String> vals = values == null ? List.of() : values;
        return NamedRestriction.named(type, params, vals, factory.apply(params, vals));
    }

    public void unbind(String type) {
        if (type != null && !BUILT_INS.contains(type)) {
            factories.remove(type);
        }
    }

    /** @see #bind(String, RestrictionRule) */
    public static void register(String type, RestrictionRule rule) {
        current().bind(type, rule);
    }

    /** @see #bind(String, Predicate) */
    public static void register(String type, Predicate<String> allowed) {
        current().bind(type, allowed);
    }

    /** @see #bind(String, Predicate, String, String) */
    public static void register(String type, Predicate<String> allowed, String code, String message) {
        current().bind(type, allowed, code, message);
    }

    /** Resolves a JSON type name against {@link #current()}. */
    public static RestrictionRule create(String type, Map<String, String> parameters, List<String> values) {
        return current().resolve(type, parameters, values);
    }

    public static RestrictionRule create(String type, Map<String, String> parameters) {
        return current().resolve(type, parameters);
    }

    public static void unregister(String type) {
        current().unbind(type);
    }

    private RestrictionRules withBuiltins() {
        factories.put("regex", (params, values) -> {
            String pattern = required(params, "pattern");
            Pattern compiled = Pattern.compile(pattern);
            return value -> compiled.matcher(value == null ? "" : value).matches()
                    ? RestrictionOutcome.allow()
                    : RestrictionOutcome.reject(ViolationCodes.VALUE_REGEX, "does not match " + pattern);
        });
        factories.put("oneOf", (params, values) -> {
            List<String> allowed = (values != null && !values.isEmpty())
                    ? List.copyOf(values)
                    : List.of(required(params, "values").split(","));
            return value -> allowed.contains(value)
                    ? RestrictionOutcome.allow()
                    : RestrictionOutcome.reject(ViolationCodes.VALUE_ONE_OF, "not in whitelist");
        });
        factories.put("maxLength", (params, values) -> {
            int max = Integer.parseInt(required(params, "max"));
            if (max < 1) {
                throw new IllegalArgumentException("maxLength max must be at least 1");
            }
            return value -> value != null && value.length() <= max
                    ? RestrictionOutcome.allow()
                    : RestrictionOutcome.reject(ViolationCodes.VALUE_MAX_LENGTH, "exceeds maxLength " + max);
        });
        factories.put("country", (params, values) -> value ->
                value != null && value.matches("[A-Z]{2}")
                        ? RestrictionOutcome.allow()
                        : RestrictionOutcome.reject(
                                ViolationCodes.VALUE_COUNTRY, "must be a two-letter ISO country code"));
        return this;
    }

    private static void requireType(String type) {
        if (type == null || type.isBlank()) {
            throw new IllegalArgumentException("restriction type is required");
        }
    }

    private static String required(Map<String, String> params, String key) {
        String value = params == null ? null : params.get(key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("restriction param '" + key + "' is required");
        }
        return value;
    }
}
