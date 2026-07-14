#!/usr/bin/env bash
# Example policy gate: fail a release script (or pre-push hook) when the
# tree contains unprotected key material or dying certificates.
#
#   bash examples/audit-gate.sh ./deploy
#
# Rules used here:
#   - plaintext private keys       → fail (default)
#   - keys readable beyond owner   → fail (default)
#   - certificates expired         → fail (default)
#   - certificates expiring ≤ 30d  → fail (--expiring 30)
#   - RSA below 2048 bits          → fail (--min-rsa-bits 2048)
set -euo pipefail

TARGET="${1:-.}"

if keysweep check --expiring 30 --min-rsa-bits 2048 "$TARGET"; then
  echo "crypto-material gate: clean"
else
  echo "crypto-material gate: fix the findings above before shipping" >&2
  exit 1
fi
