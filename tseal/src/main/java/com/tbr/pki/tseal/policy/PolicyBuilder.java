package com.tbr.pki.tseal.policy;

import com.tbr.pki.tseal.policy.builder.ClientAuthPolicyBuilder;
import com.tbr.pki.tseal.policy.builder.CustomPolicyBuilder;
import com.tbr.pki.tseal.policy.builder.CustomPolicyStart;
import com.tbr.pki.tseal.policy.builder.HttpsPolicyBuilder;
import com.tbr.pki.tseal.policy.builder.SigningPolicyBuilder;

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
