package com.tbr.pki.tseal.policy.snapshot;

import com.tbr.pki.tseal.policy.IssuancePolicy;

/**
 * Format-agnostic writer/reader for an {@link IssuancePolicy}.
 * JSON lives in the {@code tseal-policy-json} module; other formats implement this SPI.
 */
public interface PolicyCodec {

    /** Short format name, e.g. {@code json}. */
    String format();

    String write(IssuancePolicy policy);

    IssuancePolicy read(String document);
}
