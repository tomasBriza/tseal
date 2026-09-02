package com.tbr.pki.tseal.csr;

import org.bouncycastle.operator.ContentSigner;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Duration;
import java.util.function.Consumer;

public interface HttpsBuildable {
    HttpsBuildable commonName(String cn);
    HttpsBuildable dns(String dns);
    HttpsBuildable ip(String ip);
    HttpsBuildable validity(Duration duration);
    HttpsBuildable custom(Consumer<RawCsr> customizer);
    CsrResult build(KeyPair keyPair);
    CsrResult build(PublicKey publicKey, PrivateKey privateKey);
    CsrResult build(PublicKey publicKey, ContentSigner signer);
}
