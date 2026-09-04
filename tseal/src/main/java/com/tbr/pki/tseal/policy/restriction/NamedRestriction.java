package com.tbr.pki.tseal.policy.restriction;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Restriction with an optional JSON type name. Anonymous lambdas have {@code type == null}. */
public final class NamedRestriction implements RestrictionRule {

    public final String type;
    public final Map<String, String> params;
    public final List<String> values;
    private final RestrictionRule delegate;

    private NamedRestriction(String type, Map<String, String> params, List<String> values, RestrictionRule delegate) {
        this.type = type;
        this.params = params == null ? Map.of() : Map.copyOf(params);
        this.values = values == null ? List.of() : List.copyOf(values);
        this.delegate = Objects.requireNonNull(delegate, "delegate");
    }

    public static NamedRestriction named(String type, Map<String, String> params, List<String> values, RestrictionRule delegate) {
        if (type == null || type.isBlank()) {
            throw new IllegalArgumentException("restriction type is required");
        }
        return new NamedRestriction(type, params, values, delegate);
    }

    public static NamedRestriction unnamed(RestrictionRule delegate) {
        return new NamedRestriction(null, Map.of(), List.of(), delegate);
    }

    public boolean isUnnamed() {
        return type == null;
    }

    @Override
    public RestrictionOutcome evaluate(String value) {
        return delegate.evaluate(value);
    }
}
