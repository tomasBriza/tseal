package io.github.tomasbriza.tseal.policy;

import io.github.tomasbriza.tseal.policy.builder.ClientAuthPolicyBuilder;
import io.github.tomasbriza.tseal.policy.builder.CustomPolicyBuilder;
import io.github.tomasbriza.tseal.policy.builder.CustomPolicyStart;
import io.github.tomasbriza.tseal.policy.builder.HttpsPolicyBuilder;
import io.github.tomasbriza.tseal.policy.builder.SigningPolicyBuilder;

public final class PolicyBuilder {

    private PolicyBuilder() {}

    public static HttpsPolicyBuilder httpsPolicy() {
        return new HttpsPolicyBuilder();
    }

    public static ClientAuthPolicyBuilder clientAuthPolicy() {
        return new ClientAuthPolicyBuilder();
    }

    public static SigningPolicyBuilder signingPolicy() {
        return new SigningPolicyBuilder();
    }

    public static CustomPolicyStart custom() {
        return new CustomPolicyBuilder();
    }
}
