package com.tbr.pki.tseal.key;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

public final class KeyPairFactory {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private KeyPairFactory() {}

    public static KeyPair generate(KeyAlgorithm algorithm) {
        try {
            return switch (algorithm) {
                case RSA_2048, RSA_3072, RSA_4096 -> {
                    var gen = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
                    gen.initialize(algorithm.rsaKeySize());
                    yield gen.generateKeyPair();
                }
                case EC_P256, EC_P384, EC_P521 -> {
                    var gen = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
                    gen.initialize(new ECGenParameterSpec(algorithm.ecCurveName()));
                    yield gen.generateKeyPair();
                }
                case ED25519, ED448 -> {
                    var gen = KeyPairGenerator.getInstance(algorithm.jcaName(), BouncyCastleProvider.PROVIDER_NAME);
                    yield gen.generateKeyPair();
                }
            };
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("Key generation failed for " + algorithm, e);
        }
    }
}
