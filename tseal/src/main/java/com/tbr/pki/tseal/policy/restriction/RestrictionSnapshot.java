package com.tbr.pki.tseal.policy.restriction;

import java.util.List;
import java.util.Map;

public record RestrictionSnapshot(String type, Map<String, String> params, List<String> values) {

    public RestrictionSnapshot {
        params = params == null ? Map.of() : Map.copyOf(params);
        values = values == null ? List.of() : List.copyOf(values);
        if (type == null || type.isBlank()) {
            throw new IllegalArgumentException("restriction type is required");
        }
    }

    public static RestrictionSnapshot from(NamedRestriction restriction) {
        if (restriction.isUnnamed()) {
            throw new IllegalArgumentException(
                    "cannot serialize anonymous restriction; RestrictionRules.register(type, rule) first");
        }
        return new RestrictionSnapshot(restriction.type, restriction.params, restriction.values);
    }

    public RestrictionRule toRule() {
        return RestrictionRules.create(type, params, values);
    }
}
