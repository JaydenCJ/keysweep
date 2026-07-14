#!/usr/bin/env bash
# Assembles a realistic demo directory from the repository's committed
# throwaway fixtures (internal/testkeys/fixtures — generated purely for
# tests, never used to protect anything). Run it, then point keysweep at
# the result:
#
#   bash examples/make-demo-dir.sh /tmp/keysweep-demo
#   keysweep scan /tmp/keysweep-demo
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIX="$ROOT/internal/testkeys/fixtures"
DEST="${1:?usage: make-demo-dir.sh <target-dir>}"

rm -rf "$DEST"
mkdir -p "$DEST"/{ssh,legacy,pki,store,deploy}

put() { # put <fixture> <dest-rel> <mode>
  cp "$FIX/$1" "$DEST/$2"
  chmod "$3" "$DEST/$2"
}

# A typical ~/.ssh: one modern key done right, one done wrong.
put openssh_rsa3072_enc.key  ssh/id_rsa       600
put openssh_ed25519.key      ssh/id_ed25519   600
put ppk2_rsa_enc.ppk         ssh/putty.ppk    600

# The forgotten corner: plaintext keys with loose permissions.
put rsa2048_pkcs1.pem        legacy/server.key    644
put rsa2048_pkcs8_enc.pem    legacy/server-enc.key 600
put dsa1024.pem              legacy/ancient.key   644

# TLS material: a live chain, an expired cert, a pending CSR.
put fullchain.pem            pki/fullchain.pem    644
put cert_expired.pem         pki/old.crt          644
put csr.pem                  pki/req.csr          644

# Password-wrapped bundles.
put bundle.p12               store/bundle.p12     600
put keystore.jks             store/keystore.jks   600

# A key pasted into a config file — the kind nobody remembers.
put embedded.env             deploy/.env          600

# Noise that must yield no findings.
printf 'demo tree for keysweep — every key here is a throwaway fixture\n' > "$DEST/README.txt"

echo "demo tree ready at $DEST"
