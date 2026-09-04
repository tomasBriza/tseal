package com.tbr.pki.tseal.policy;

public record PolicyViolation(String field, String message, String code) {

    public PolicyViolation(String field, String message) {
        this(field, message, ViolationCodes.POLICY);
    }

    public PolicyViolation {
        if (field == null || field.isBlank()) {
            throw new IllegalArgumentException("field");
        }
        if (message == null || message.isBlank()) {
            throw new IllegalArgumentException("message");
        }
        if (code == null || code.isBlank()) {
            throw new IllegalArgumentException("code");
        }
    }

    @Override
    public String toString() {
        return code + " " + field + ": " + message;
    }
}
