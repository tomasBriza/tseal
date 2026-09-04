package com.tbr.pki.tseal.issue;

import org.bouncycastle.operator.ContentSigner;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public interface IssueWithPolicy {
    IssueBuildable using(X509Certificate issuerCertificate, PrivateKey issuerKey);
    IssueBuildable using(X509Certificate issuerCertificate, KeyPair issuerKeyPair);
    IssueBuildable using(X509Certificate issuerCertificate, ContentSigner signer);
    IssueBuildable selfSigned(PrivateKey subjectKey);
    IssueBuildable selfSigned(KeyPair subjectKeyPair);
}
