package com.tbr.pki.tseal.csr;

import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.operator.ContentSigner;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Duration;
import java.util.function.Consumer;

/**
 * Single impl class typed as HttpsStart by the factory method.
 * dns()/ip() return this typed as HttpsBuildable, unlocking build().
 * Covariant return types satisfy both interface contracts from one method each.
 */
final class HttpsPolicyBuilder implements HttpsStart, HttpsBuildable {

    private final CsrAccumulator accumulator = new CsrAccumulator();

    HttpsPolicyBuilder() {
        accumulator.adaptiveKeyUsage = true;
        accumulator.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        accumulator.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
    }

    @Override
    public HttpsPolicyBuilder commonName(String cn) {
        accumulator.subjectBuilder.addRDN(BCStyle.CN, cn);
        return this;
    }

    @Override
    public HttpsBuildable dns(String dns) {
        accumulator.sanEntries.add(new GeneralName(GeneralName.dNSName, dns));
        return this;
    }

    @Override
    public HttpsBuildable ip(String ip) {
        accumulator.sanEntries.add(new GeneralName(GeneralName.iPAddress, ip));
        return this;
    }

    @Override
    public HttpsPolicyBuilder validity(Duration duration) {
        accumulator.requestedValidity(duration);
        return this;
    }

    @Override
    public HttpsPolicyBuilder custom(Consumer<RawCsr> customizer) {
        customizer.accept(new RawCsrImpl(accumulator));
        return this;
    }

    @Override
    public CsrResult build(KeyPair keyPair) {
        return CsrEngine.build(accumulator, keyPair.getPublic(), keyPair.getPrivate(), null);
    }

    @Override
    public CsrResult build(PublicKey publicKey, PrivateKey privateKey) {
        return CsrEngine.build(accumulator, publicKey, privateKey, null);
    }

    @Override
    public CsrResult build(PublicKey publicKey, ContentSigner signer) {
        return CsrEngine.build(accumulator, publicKey, null, signer);
    }
}
