package com.tbr.pki.tseal.policy.json;

/** Resolves a policy document id used in JSON {@code extends}. */
@FunctionalInterface
public interface PolicyDocumentResolver {
    String read(String id);
}
