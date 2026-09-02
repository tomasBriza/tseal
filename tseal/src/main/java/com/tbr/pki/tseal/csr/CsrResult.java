package com.tbr.pki.tseal.csr;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

public record CsrResult(PKCS10CertificationRequest request, String pem) {}
