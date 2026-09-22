package io.github.tomasbriza.tseal.policy.json;

import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class PolicySnapshotMixin {
    @JsonProperty("extends")
    public abstract String extendsFrom();
}
