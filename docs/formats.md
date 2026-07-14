# Detection reference

keysweep identifies material by **content, not file extension**. Every rule
below is implemented in `internal/parse` and covered by the test suite.
Nothing is ever decrypted; protection state is read from headers and
envelopes that the formats expose in the clear by design.

## Dispatch order

For each candidate file (regular, within the size cap, not excluded):

1. **Java keystore magic** — `FE ED FE ED` → `jks`, `CE CE CE CE` → `jceks`.
2. **PuTTY header** — files starting `PuTTY-User-Key-File-<v>:` (v1–v3).
3. **PEM blocks** — any occurrence of `-----BEGIN …-----`, anywhere in the
   file, including keys pasted into `.env`/YAML/config files. Every block
   in the file is classified; each finding records the 1-based line of its
   marker.
4. **Bare DER** — files whose first byte is the ASN.1 SEQUENCE tag (`0x30`)
   are run through the strict stdlib parsers: certificate → PKCS#8 key →
   PKCS#1 key → SEC1 key → encrypted PKCS#8 → PKCS#12 envelope.

## PEM block types

| PEM type | Kind | Format | What is recovered |
|---|---|---|---|
| `RSA PRIVATE KEY` | private-key | `pkcs1-pem` | modulus bits; `DEK-Info` cipher if encrypted |
| `PRIVATE KEY` | private-key | `pkcs8-pem` | algorithm, curve, bits (RSA / ECDSA / Ed25519 / X25519) |
| `ENCRYPTED PRIVATE KEY` | private-key | `pkcs8-pem` | cipher + KDF from the PBES2/PBE envelope |
| `EC PRIVATE KEY` | private-key | `sec1-pem` | curve and field size |
| `DSA PRIVATE KEY` | private-key | `dsa-pem` | key size from the ASN.1 prime *p* |
| `OPENSSH PRIVATE KEY` | private-key | `openssh` | algorithm, bits, cipher (see below) |
| `CERTIFICATE` | certificate | `x509-pem` | subject, issuer, validity, key algo/bits, self-signed, CA |
| `CERTIFICATE REQUEST` | certificate-request | `csr-pem` | subject, key algo/bits |
| any other `… PRIVATE KEY` | private-key | `pem` | counted, fields honest-unknown |

Public keys, DH parameters, and other non-secret blocks are ignored.

## Why encrypted keys still show their size

- **openssh-key-v1** stores the cipher name, KDF, and the *public* key blob
  unencrypted — so an `aes256-ctr`-protected RSA key still reports
  `rsa 3072`.
- **PuTTY .ppk** stores the algorithm and `Encryption:` header plus the
  public blob in the clear.
- **Encrypted PKCS#8** hides the key type, but names its own cipher: the
  `EncryptedPrivateKeyInfo` envelope carries the PBES2 scheme (e.g.
  `aes-256-cbc (pbkdf2)`), which keysweep decodes from the OIDs.
- **Legacy OpenSSL PEM** (`Proc-Type: 4,ENCRYPTED`) names the cipher in the
  `DEK-Info` header; the key size is unknowable and reported as `-`.

## Protection states

| State | Meaning |
|---|---|
| `plaintext` | anyone who can read the file owns the key |
| `encrypted` | a passphrase is required; the cipher is reported |
| `password` | the format is always password-wrapped (PKCS#12, JKS) — the password may still be empty |
| `none` | material with no secret (certificates, CSRs) |

## Permissions

A private key or container whose mode grants **any** group/other bit
(`mode & 0o077 != 0`) is flagged with `!` — the same test OpenSSH applies
before refusing an identity file. `check` fails on it unless
`--ignore-perms` is set.

## Deliberate non-goals

- **No decryption attempts, ever** — keysweep never prompts for, guesses,
  or accepts passphrases.
- **No API-key / token string matching** — that is a secret-scanner's job
  (gitleaks, trufflehog). keysweep inventories cryptographic *files*.
- **No network** — revocation status, CT logs, and OCSP are out of scope.
