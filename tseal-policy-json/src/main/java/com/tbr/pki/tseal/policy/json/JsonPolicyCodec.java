package com.tbr.pki.tseal.policy.json;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.tbr.pki.tseal.policy.IssuancePolicy;
import com.tbr.pki.tseal.policy.PolicyCodec;
import com.tbr.pki.tseal.policy.PolicySnapshot;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

/**
 * JSON {@link PolicyCodec}. Jackson is an implementation detail and is not part of the
 * public API.
 */
public final class JsonPolicyCodec implements PolicyCodec {

    private final ObjectMapper mapper;

    public JsonPolicyCodec() {
        this(new ObjectMapper()
                .setSerializationInclusion(JsonInclude.Include.NON_EMPTY)
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                .enable(SerializationFeature.INDENT_OUTPUT));
    }

    JsonPolicyCodec(ObjectMapper mapper) {
        this.mapper = Objects.requireNonNull(mapper, "mapper");
    }

    @Override
    public String format() {
        return "json";
    }

    @Override
    public String write(IssuancePolicy policy) {
        Objects.requireNonNull(policy, "policy");
        try {
            return mapper.writeValueAsString(policy.snapshot());
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Failed to write policy JSON", e);
        }
    }

    @Override
    public IssuancePolicy read(String document) {
        if (document == null || document.isBlank()) {
            throw new IllegalArgumentException("policy JSON must be non-blank");
        }
        try {
            return mapper.readValue(document, PolicySnapshot.class).toPolicy();
        } catch (JsonProcessingException e) {
            throw unwrap(e);
        }
    }

    public void write(IssuancePolicy policy, Path path) throws IOException {
        Files.writeString(path, write(policy));
    }

    public IssuancePolicy read(Path path) throws IOException {
        return read(Files.readString(path));
    }

    private static IllegalArgumentException unwrap(JsonProcessingException e) {
        Throwable current = e;
        while (current != null) {
            if (current instanceof IllegalArgumentException iae && !(current instanceof JsonProcessingException)) {
                return iae;
            }
            current = current.getCause();
        }
        return new IllegalArgumentException("Failed to read policy JSON", e);
    }
}
