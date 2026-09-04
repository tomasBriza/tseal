package com.tbr.pki.tseal.policy.json;

import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class PolicySnapshotMixin {
    @JsonProperty("extends")
    public abstract String extendsFrom();
}
