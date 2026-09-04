package com.tbr.pki.tseal.issue;

import com.tbr.pki.tseal.policy.CallerValues;

import org.bouncycastle.operator.ContentSigner;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.util.function.BiConsumer;

public interface IssueBuildable {
    IssueBuildable caller(CallerValues caller);
    IssueBuildable clock(Clock clock);
    IssueBuildable serial(BigInteger serial);
    IssueBuildable backdate(Duration skew);
    IssueBuildable customize(BiConsumer<CallerValues, RawIssuedCertificate> customizer);
    IssueBuildable using(X509Certificate issuerCertificate, PrivateKey issuerKey);
    IssueBuildable using(X509Certificate issuerCertificate, KeyPair issuerKeyPair);
    IssueBuildable using(X509Certificate issuerCertificate, ContentSigner signer);
    IssueBuildable selfSigned(PrivateKey subjectKey);
    IssueBuildable selfSigned(KeyPair subjectKeyPair);
    IssuedCertificate issue();
}
