package com.tbr.pki.tseal.policy;

import java.time.Duration;
import java.util.Objects;

public final class ValidityRule {

    public enum Mode { FROM_CSR, EXACTLY, FORBIDDEN }

    public final Mode mode;
    public final boolean optional;
    public final boolean orCaller;
    public final Duration exactValue;
    public final Duration defaultValue;
    public final Duration min;
    public final Duration max;

    private ValidityRule(
            Mode mode,
            boolean optional,
            boolean orCaller,
            Duration exactValue,
            Duration defaultValue,
            Duration min,
            Duration max) {
        this.mode = mode;
        this.optional = optional;
        this.orCaller = orCaller;
        this.exactValue = exactValue;
        this.defaultValue = defaultValue;
        this.min = min;
        this.max = max;
    }

    public static ValidityRule fromCsr() {
        return new ValidityRule(Mode.FROM_CSR, false, false, null, null, null, null);
    }

    public static ValidityRule exactly(Duration duration) {
        return new ValidityRule(Mode.EXACTLY, false, false, requirePositive(duration, "exact"), null, null, null);
    }

    public static ValidityRule forbidden() {
        return new ValidityRule(Mode.FORBIDDEN, false, false, null, null, null, null);
    }

    public static ValidityRule fromSnapshot(String mode, boolean optional, boolean orCaller,
                                     String exact, String orDefault, String min, String max) {
        ValidityRule rule = switch (parseMode(mode)) {
            case FROM_CSR -> fromCsr();
            case EXACTLY -> exactly(parseDuration(exact, "exact"));
            case FORBIDDEN -> forbidden();
        };
        if (optional) {
            rule = rule.optional();
        }
        if (orCaller) {
            rule = rule.orCaller();
        }
        if (orDefault != null) {
            rule = rule.orDefault(parseDuration(orDefault, "orDefault"));
        }
        if (min != null) {
            rule = rule.min(parseDuration(min, "min"));
        }
        if (max != null) {
            rule = rule.max(parseDuration(max, "max"));
        }
        return rule;
    }

    public static Mode parseMode(String mode) {
        if (mode == null || mode.isBlank()) {
            throw new IllegalArgumentException("validity rule mode is required");
        }
        return switch (mode) {
            case "fromCsr", "FROM_CSR" -> Mode.FROM_CSR;
            case "exactly", "EXACTLY" -> Mode.EXACTLY;
            case "forbidden", "FORBIDDEN" -> Mode.FORBIDDEN;
            default -> throw new IllegalArgumentException("unknown validity rule mode: " + mode);
        };
    }

    public static String modeName(Mode mode) {
        return switch (mode) {
            case FROM_CSR -> "fromCsr";
            case EXACTLY -> "exactly";
            case FORBIDDEN -> "forbidden";
        };
    }

    public static String formatDuration(Duration duration) {
        if (duration == null) {
            return null;
        }
        long seconds = duration.toSeconds();
        if (seconds % 86_400 == 0) {
            return "P" + (seconds / 86_400) + "D";
        }
        if (seconds % 3_600 == 0) {
            return "PT" + (seconds / 3_600) + "H";
        }
        return duration.toString();
    }

    public static Duration parseDuration(String value, String what) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(what + " duration is required");
        }
        try {
            return Duration.parse(value);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException(what + " duration is not ISO-8601: " + value, e);
        }
    }

    public ValidityRule optional() {
        return copy(mode, true, orCaller, exactValue, defaultValue, min, max);
    }

    public ValidityRule orCaller() {
        return copy(mode, optional, true, exactValue, defaultValue, min, max);
    }

    public ValidityRule orDefault(Duration duration) {
        return copy(mode, optional, orCaller, exactValue, requirePositive(duration, "default"), min, max);
    }

    public ValidityRule min(Duration min) {
        return copy(mode, optional, orCaller, exactValue, defaultValue, requirePositive(min, "min"), max);
    }

    public ValidityRule max(Duration max) {
        return copy(mode, optional, orCaller, exactValue, defaultValue, min, requirePositive(max, "max"));
    }

    public void validateStatically() {
        if (min != null && max != null && min.compareTo(max) > 0) {
            throw new IllegalArgumentException("validity min must be <= max");
        }
        if (mode == Mode.FORBIDDEN && !orCaller && defaultValue == null) {
            throw new IllegalArgumentException("forbidden validity requires orCaller() or orDefault(...)");
        }
        checkRange(exactValue);
        checkRange(defaultValue);
    }

    public boolean inRange(Duration duration) {
        if (duration == null) {
            return false;
        }
        if (min != null && duration.compareTo(min) < 0) {
            return false;
        }
        if (max != null && duration.compareTo(max) > 0) {
            return false;
        }
        return true;
    }

    public String rangeMessage(Duration duration) {
        if (min != null && duration.compareTo(min) < 0) {
            return "below min " + min;
        }
        if (max != null && duration.compareTo(max) > 0) {
            return "above max " + max;
        }
        return "invalid";
    }

    private void checkRange(Duration duration) {
        if (duration != null && !inRange(duration)) {
            throw new IllegalArgumentException("validity " + rangeMessage(duration));
        }
    }

    public static Duration requirePositive(Duration duration, String what) {
        Objects.requireNonNull(duration, what);
        if (duration.isNegative() || duration.toSeconds() <= 0) {
            throw new IllegalArgumentException(what + " validity must be at least one second");
        }
        return duration;
    }

    private static ValidityRule copy(
            Mode mode,
            boolean optional,
            boolean orCaller,
            Duration exactValue,
            Duration defaultValue,
            Duration min,
            Duration max) {
        return new ValidityRule(mode, optional, orCaller, exactValue, defaultValue, min, max);
    }
}
