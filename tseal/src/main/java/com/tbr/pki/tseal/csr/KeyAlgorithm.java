package com.tbr.pki.tseal.csr;

public enum KeyAlgorithm {
    RSA_2048("RSA", 2048, null),
    RSA_3072("RSA", 3072, null),
    RSA_4096("RSA", 4096, null),
    EC_P256("EC", 0, "P-256"),
    EC_P384("EC", 0, "P-384"),
    EC_P521("EC", 0, "P-521"),
    ED25519("Ed25519", 0, null),
    ED448("Ed448", 0, null);

    private final String jcaName;
    private final int rsaKeySize;
    private final String ecCurveName;

    KeyAlgorithm(String jcaName, int rsaKeySize, String ecCurveName) {
        this.jcaName = jcaName;
        this.rsaKeySize = rsaKeySize;
        this.ecCurveName = ecCurveName;
    }

    String jcaName() { return jcaName; }
    int rsaKeySize() { return rsaKeySize; }
    String ecCurveName() { return ecCurveName; }
}
