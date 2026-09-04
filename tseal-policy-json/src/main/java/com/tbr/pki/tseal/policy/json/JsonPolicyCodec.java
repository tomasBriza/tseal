package com.tbr.pki.tseal.policy.json;

import com.tbr.pki.tseal.policy.IssuancePolicy;
import com.tbr.pki.tseal.policy.snapshot.PolicyCodec;
import com.tbr.pki.tseal.policy.snapshot.PolicySnapshot;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;

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
                .enable(SerializationFeature.INDENT_OUTPUT)
                .addMixIn(PolicySnapshot.class, PolicySnapshotMixin.class));
    }

    public JsonPolicyCodec(ObjectMapper mapper) {
        this.mapper = Objects.requireNonNull(mapper, "mapper");
        mapper.addMixIn(PolicySnapshot.class, PolicySnapshotMixin.class);
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
        return read(document, null);
    }

    public IssuancePolicy read(String document, PolicyDocumentResolver resolver) {
        if (document == null || document.isBlank()) {
            throw new IllegalArgumentException("policy JSON must be non-blank");
        }
        try {
            JsonNode root = mapper.readTree(document);
            JsonNode extendsNode = root.get("extends");
            if (extendsNode != null && !extendsNode.isNull()) {
                if (extendsNode.isTextual()) {
                    if (resolver == null) {
                        throw new IllegalArgumentException("extends requires a PolicyDocumentResolver");
                    }
                    String baseJson = resolver.read(extendsNode.asText());
                    if (baseJson == null || baseJson.isBlank()) {
                        throw new IllegalArgumentException("extends document is empty: " + extendsNode.asText());
                    }
                    JsonNode base = mapper.readTree(baseJson);
                    if (!(base instanceof ObjectNode baseObj) || !(root instanceof ObjectNode overlay)) {
                        throw new IllegalArgumentException("extends merge requires JSON objects");
                    }
                    ObjectNode merged = mergeObject(baseObj, overlay);
                    merged.remove("extends");
                    return mapper.treeToValue(merged, PolicySnapshot.class).toPolicy();
                }
                throw new IllegalArgumentException("extends must be a document id string");
            }
            return mapper.treeToValue(root, PolicySnapshot.class).toPolicy();
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

    public IssuancePolicy read(Path path, PolicyDocumentResolver resolver) throws IOException {
        return read(Files.readString(path), resolver);
    }

    public static ObjectNode mergeObject(ObjectNode base, ObjectNode overlay) {
        ObjectNode out = base.deepCopy();
        Iterator<Map.Entry<String, JsonNode>> fields = overlay.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            String key = entry.getKey();
            if ("extends".equals(key)) {
                continue;
            }
            JsonNode value = entry.getValue();
            if (value.isObject()
                    && out.get(key) instanceof ObjectNode existing
                    && ("subject".equals(key) || "san".equals(key) || "otherNames".equals(key))) {
                ObjectNode merged = existing.deepCopy();
                value.fields().forEachRemaining(nested -> merged.set(nested.getKey(), nested.getValue()));
                out.set(key, merged);
            } else {
                out.set(key, value);
            }
        }
        return out;
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
