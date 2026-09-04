package com.tbr.pki.tseal.csr.builder;

import com.tbr.pki.tseal.csr.CsrResult;
import com.tbr.pki.tseal.csr.RawCsr;
import com.tbr.pki.tseal.csr.engine.CsrAccumulator;
import com.tbr.pki.tseal.csr.engine.CsrEngine;
import com.tbr.pki.tseal.csr.engine.RawCsrImpl;

import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.operator.ContentSigner;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Duration;
import java.util.function.Consumer;

public final class SigningCertBuilder {

    private final CsrAccumulator accumulator = new CsrAccumulator();

    public SigningCertBuilder() {
        accumulator.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        accumulator.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
    }

    public SigningCertBuilder commonName(String cn) {
        accumulator.subjectBuilder.addRDN(BCStyle.CN, cn);
        return this;
    }

    public SigningCertBuilder organization(String o) {
        accumulator.subjectBuilder.addRDN(BCStyle.O, o);
        return this;
    }

    public SigningCertBuilder validity(Duration duration) {
        accumulator.requestedValidity(duration);
        return this;
    }

    public SigningCertBuilder custom(Consumer<RawCsr> customizer) {
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
