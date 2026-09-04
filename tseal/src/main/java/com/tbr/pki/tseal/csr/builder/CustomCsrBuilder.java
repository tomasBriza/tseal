package com.tbr.pki.tseal.csr.builder;

import com.tbr.pki.tseal.csr.CsrResult;
import com.tbr.pki.tseal.csr.RawCsr;
import com.tbr.pki.tseal.csr.engine.CsrAccumulator;
import com.tbr.pki.tseal.csr.engine.CsrEngine;
import com.tbr.pki.tseal.csr.engine.RawCsrImpl;

import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.operator.ContentSigner;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Duration;
import java.util.function.Consumer;

public final class CustomCsrBuilder {

    private final CsrAccumulator accumulator = new CsrAccumulator();

    public CustomCsrBuilder() {}

    public SubjectBuilder<CustomCsrBuilder> subject() {
        return new SubjectBuilder<>(accumulator, this);
    }

    public SanBuilder<CustomCsrBuilder> san() {
        return new SanBuilder<>(accumulator, this);
    }

    public CustomCsrBuilder keyUsage(int bits) {
        accumulator.addExtension(Extension.keyUsage, true, new KeyUsage(bits));
        return this;
    }

    public CustomCsrBuilder extendedKeyUsage(KeyPurposeId... purposes) {
        accumulator.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(purposes));
        return this;
    }

    public CustomCsrBuilder validity(Duration duration) {
        accumulator.requestedValidity(duration);
        return this;
    }

    public CustomCsrBuilder custom(Consumer<RawCsr> customizer) {
        customizer.accept(new RawCsrImpl(accumulator));
        return this;
    }

    public CsrResult build(KeyPair keyPair) {
        return CsrEngine.build(accumulator, keyPair.getPublic(), keyPair.getPrivate(), null);
    }

    public CsrResult build(PublicKey publicKey, PrivateKey privateKey) {
        return CsrEngine.build(accumulator, publicKey, privateKey, null);
    }

    public CsrResult build(PublicKey publicKey, ContentSigner signer) {
        return CsrEngine.build(accumulator, publicKey, null, signer);
    }
}
