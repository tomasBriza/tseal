# Java KeyStore

No `KeyStore` type. Inputs and outputs are JCA `PrivateKey`, `PublicKey`, `KeyPair`, and `X509Certificate`. PKCS#12, JKS, and PKCS#11 stay on `java.security.KeyStore`.

PEM is [`Certificates`](../pem/readme.md), [`PublicKeys`](../pem/readme.md), and [`PrivateKeys`](../pem/readme.md). `Certificates.writeChain` keeps the order you pass. It does not validate the chain.

Note: maybe provide wrapper later if needed.