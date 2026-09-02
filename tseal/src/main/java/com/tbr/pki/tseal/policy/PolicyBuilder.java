package com.tbr.pki.tseal.policy;

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
