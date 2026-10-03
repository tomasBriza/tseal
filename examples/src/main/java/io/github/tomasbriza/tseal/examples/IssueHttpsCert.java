package io.github.tomasbriza.tseal.examples;

import io.github.tomasbriza.tseal.csr.CsrBuilder;
import io.github.tomasbriza.tseal.csr.CsrResult;
import io.github.tomasbriza.tseal.issue.CertificateIssuer;
import io.github.tomasbriza.tseal.issue.IssueResult;
import io.github.tomasbriza.tseal.key.KeyAlgorithm;
import io.github.tomasbriza.tseal.key.KeyPairFactory;
import io.github.tomasbriza.tseal.policy.Evaluation;
import io.github.tomasbriza.tseal.policy.IssuancePolicy;
import io.github.tomasbriza.tseal.policy.PolicyBuilder;
import io.github.tomasbriza.tseal.policy.PolicyViolation;
import io.github.tomasbriza.tseal.policy.json.JsonPolicyCodec;
import io.github.tomasbriza.tseal.policy.snapshot.PolicyCodec;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.List;

import static io.github.tomasbriza.tseal.policy.Rules.fromCsr;

/**
 * Root plus a TLS leaf. Writes PEM, PKCS#12, and the policy JSON next to the working directory.
 * Policy misses are results. A bad CSR signature or a non-CA issuer still throws.
 */
public final class IssueHttpsCert {

    public static void main(String[] args) throws Exception {
        Path out = Path.of(args.length > 0 ? args[0] : ".");
        Files.createDirectories(out);

        KeyPair caKeys = KeyPairFactory.generate(KeyAlgorithm.EC_P256);
        KeyPair leafKeys = KeyPairFactory.generate(KeyAlgorithm.EC_P256);

        IssueResult.Issued ca = switch (CertificateIssuer.issue()
                .csr(CsrBuilder.signingCsr().commonName("POC Root").build(caKeys).request())
                .policy(PolicyBuilder.signingPolicy().build())
                .selfSigned(caKeys)
                .issue()) {
            case IssueResult.Rejected(var violations) ->
                throw new IllegalStateException(violations.toString());
            case IssueResult.Issued r -> r;
        };

        IssuancePolicy policy = PolicyBuilder.httpsPolicy()
                .dns(fromCsr().matching(".*\\.example\\.test"))
                .build();

        CsrResult csr = CsrBuilder.httpsCsr()
                .commonName("app")
                .dns("app.example.test")
                .build(leafKeys);

        switch (policy.check(csr.request())) {
            case Evaluation.Violations(var violations) ->
                    throw new IllegalStateException(violations.toString());
            case Evaluation.Ok ignored -> { }
        }

        IssueResult.Issued leaf = switch (CertificateIssuer.issue()
                .csr(csr.request())
                .policy(policy)
                .using(ca.certificate(), caKeys.getPrivate())
                .issue()) {
            case IssueResult.Rejected(var violations) -> throw new IllegalStateException(violations.toString());
            case IssueResult.Issued l -> l;
        };

        Files.writeString(out.resolve("root.pem"), ca.pem());
        Files.writeString(out.resolve("leaf.pem"), leaf.pem());
        Files.writeString(out.resolve("fullchain.pem"), leaf.pem() + ca.pem());
        Files.writeString(out.resolve("app.csr.pem"), csr.pem());

        PolicyCodec json = new JsonPolicyCodec();
        Files.writeString(out.resolve("https-policy.json"), json.write(policy));

        char[] password = "changeit".toCharArray();
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("app", leafKeys.getPrivate(), password,
                new Certificate[] { leaf.certificate(), ca.certificate() });
        try (OutputStream store = Files.newOutputStream(out.resolve("app.p12"))) {
            ks.store(store, password);
        }

        System.out.println("wrote " + out.toAbsolutePath().normalize());
        System.out.println("openssl verify -CAfile root.pem leaf.pem");
    }

}
