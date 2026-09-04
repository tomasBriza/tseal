package com.tbr.pki.tseal.policy.restriction;

public sealed interface RestrictionOutcome {

    public record Allow() implements RestrictionOutcome {}

    public record Reject(String code, String message) implements RestrictionOutcome {
        public Reject {
            if (code == null || code.isBlank()) {
                throw new IllegalArgumentException("code");
            }
            if (message == null || message.isBlank()) {
                throw new IllegalArgumentException("message");
            }
        }
    }

    public static RestrictionOutcome allow() {
        return new Allow();
    }

    public static RestrictionOutcome reject(String code, String message) {
        return new Reject(code, message);
    }
}
