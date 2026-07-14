# Contributing to keysweep

Issues, discussions and pull requests are all welcome.

## Getting started

You need Go ≥1.22 and bash; nothing else — the test suite and smoke script
are fully offline.

```bash
git clone https://github.com/JaydenCJ/keysweep && cd keysweep
go build ./...
go test ./...
bash scripts/smoke.sh
```

`scripts/smoke.sh` builds the binary, assembles a demo tree from the
committed throwaway fixtures, and asserts on real CLI output across every
subcommand, format, and exit code; it must finish by printing `SMOKE OK`.

## Before you open a pull request

1. `gofmt -l .` reports nothing (formatting is enforced).
2. `go vet ./...` passes with no findings.
3. `go test ./...` passes (92 deterministic tests, no network).
4. `bash scripts/smoke.sh` prints `SMOKE OK`.
5. Add tests for behavior changes; keep logic in pure, unit-testable
   modules (parsers never touch the filesystem — only `sweep` does).

## Ground rules

- Keep dependencies at zero; adding one needs strong justification in the PR.
- No network calls, ever, and **no decryption, ever** — keysweep must never
  prompt for, accept, or guess a passphrase. Protection state is read only
  from headers and envelopes the formats expose in the clear. No telemetry.
- Detection rules are code + fixtures: a new format needs a committed
  throwaway fixture in `internal/testkeys/fixtures/` (generated for this
  repo, never used anywhere real), a parser test reproducing the real file
  shape, and a row in `docs/formats.md`.
- Code comments and doc comments are written in English.
- Determinism first: identical trees must produce byte-identical reports,
  including all orderings; expiry math takes an explicit `now`.

## Reporting bugs

Include the output of `keysweep version`, the full command you ran, and —
for misclassifications — the offending file's format details rather than
the file itself (`openssl asn1parse -i -in <file> | head` or the first PEM
header line). Never attach a real private key to an issue; reproduce with
a freshly generated throwaway key instead.

## Security

Please do not open public issues for security problems; use GitHub's
private vulnerability reporting on this repository instead.
