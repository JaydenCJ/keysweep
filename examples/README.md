# keysweep examples

Both scripts are offline and idempotent.

| Script | What it shows |
|---|---|
| `make-demo-dir.sh <dir>` | Builds a realistic demo tree (SSH keys, a legacy plaintext key with loose permissions, a TLS chain, an expired cert, a PKCS#12 bundle, a key pasted into `.env`) from the repository's committed throwaway fixtures. |
| `audit-gate.sh [dir]` | A release/pre-push gate built on `keysweep check`: fails on plaintext keys, loose permissions, expired or soon-expiring certificates, and sub-2048-bit RSA. |

Typical session:

```bash
go build -o keysweep ./cmd/keysweep
bash examples/make-demo-dir.sh /tmp/keysweep-demo
./keysweep scan /tmp/keysweep-demo
./keysweep check /tmp/keysweep-demo   # exits 1: the demo tree is risky on purpose
```

Every key and certificate under `internal/testkeys/fixtures/` was generated
solely for this repository's tests and demos. None has ever protected
anything — do not reuse them for real.
