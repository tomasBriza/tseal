package com.tbr.pki.tseal.csr;

public final class CsrBuilder {

    private CsrBuilder() {}

    public static HttpsStart httpsCsr() {
        return new HttpsPolicyBuilder();
    }

    public static ClientAuthBuilder clientAuthCsr() {
        return new ClientAuthBuilder();
    }

    public static SigningCertBuilder signingCsr() {
        return new SigningCertBuilder();
    }

    public static CustomCsrBuilder custom() {
        return new CustomCsrBuilder();
    }
}
