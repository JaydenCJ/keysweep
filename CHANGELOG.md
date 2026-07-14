# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-13

### Added

- Content-based detection of private keys, certificates, CSRs, and
  keystore containers — extensions are never trusted: PEM blocks anywhere
  in any file (with the 1-based line of each marker), openssh-key-v1,
  PuTTY `.ppk` v1–3, bare DER (PKCS#1/PKCS#8/SEC1/X.509), PKCS#12/PFX
  envelopes, and JKS/JCEKS magic numbers.
- Protection-state reporting without decryption: legacy `DEK-Info`
  ciphers, PBES2/PBE cipher + KDF from encrypted-PKCS#8 OIDs, OpenSSH and
  PPK cipher headers; key size recovered from the cleartext public blob
  even for passphrase-protected OpenSSH/PPK keys.
- Certificate intelligence: subject, issuer, validity with day counts,
  expired / expiring-soon status, self-signed and CA flags, public-key
  algorithm and size, for PEM chains and DER alike.
- Permission audit flagging any private key or container readable beyond
  its owner (the OpenSSH `0o077` test).
- `scan` subcommand with aligned text tables, stable JSON
  (`schema_version: 1`), and Markdown output; deterministic ordering;
  default pruning of `.git`/`node_modules`-style directories with `--all`
  override; repeatable `--exclude` globs supporting `*`, `?`, and `**`;
  size caps and a bounded parallel worker pool.
- `check` subcommand enforcing plaintext-key, loose-permissions,
  expired/expiring-certificate, and `--min-rsa-bits` rules with exit
  code 1 on breach, in text and JSON.
- Runnable examples (`examples/make-demo-dir.sh`, `examples/audit-gate.sh`)
  and a detection reference (`docs/formats.md`).
- 92 deterministic offline tests (parsers, glob matcher, filesystem sweep,
  policy rules, renderers, in-process CLI integration) and
  `scripts/smoke.sh`.

[0.1.0]: https://github.com/JaydenCJ/keysweep/releases/tag/v0.1.0
