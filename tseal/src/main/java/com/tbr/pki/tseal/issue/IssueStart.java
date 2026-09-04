package com.tbr.pki.tseal.issue;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

public interface IssueStart {
    IssueWithCsr csr(PKCS10CertificationRequest csr);
    IssueWithCsr csr(String pem);
}
