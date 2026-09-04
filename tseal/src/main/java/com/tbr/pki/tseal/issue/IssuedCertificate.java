package com.tbr.pki.tseal.issue;

import java.security.cert.X509Certificate;

/** A signed certificate plus its PEM encoding. */
public record IssuedCertificate(X509Certificate certificate, String pem) {}
