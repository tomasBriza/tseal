package io.github.tomasbriza.tseal.csr;

import io.github.tomasbriza.tseal.csr.builder.ClientAuthBuilder;
import io.github.tomasbriza.tseal.csr.builder.CustomCsrBuilder;
import io.github.tomasbriza.tseal.csr.builder.HttpsCsrBuilder;
import io.github.tomasbriza.tseal.csr.builder.HttpsStart;
import io.github.tomasbriza.tseal.csr.builder.SigningCertBuilder;

public final class CsrBuilder {

    private CsrBuilder() {}

    public static HttpsStart httpsCsr() {
        return new HttpsCsrBuilder();
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
