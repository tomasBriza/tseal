# examples

Issues a POC root and a TLS leaf. `check` returns `Evaluation`. `issue` returns `IssueResult`. `Rejected` is printed and the program stops.

From the repo root:

```bash
./gradlew :examples:run
openssl verify -CAfile root.pem leaf.pem
```

Writes `root.pem`, `leaf.pem`, `fullchain.pem`, `app.csr.pem`, `https-policy.json`, and `app.p12` (password `changeit`) into the working directory. Pass a directory as the program argument to write elsewhere.
