package com.tbr.pki.tseal.csr;

import java.time.Duration;
import java.util.function.Consumer;

public interface HttpsStart {
    HttpsStart commonName(String cn);
    HttpsBuildable dns(String dns);
    HttpsBuildable ip(String ip);
    HttpsStart validity(Duration duration);
    HttpsStart custom(Consumer<RawCsr> customizer);
}
