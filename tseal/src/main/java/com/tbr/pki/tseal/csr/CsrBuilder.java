package com.tbr.pki.tseal.csr;

import com.tbr.pki.tseal.csr.builder.ClientAuthBuilder;
import com.tbr.pki.tseal.csr.builder.CustomCsrBuilder;
import com.tbr.pki.tseal.csr.builder.HttpsCsrBuilder;
import com.tbr.pki.tseal.csr.builder.HttpsStart;
import com.tbr.pki.tseal.csr.builder.SigningCertBuilder;

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
