#!/usr/bin/env bash
# End-to-end smoke test for keysweep: builds the binary, assembles a demo
# tree from committed throwaway fixtures, and asserts on real CLI output
# across every subcommand and exit code. No network, idempotent, seconds.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

fail() {
  echo "SMOKE FAIL: $*" >&2
  exit 1
}

BIN="$WORKDIR/keysweep"
DEMO="$WORKDIR/demo"

echo "1. build"
(cd "$ROOT" && go build -o "$BIN" ./cmd/keysweep) || fail "go build failed"

echo "2. version matches manifest"
"$BIN" version | grep -qx "keysweep 0.1.0" || fail "version mismatch"

echo "3. assemble the demo tree"
bash "$ROOT/examples/make-demo-dir.sh" "$DEMO" >/dev/null

echo "4. text report inventories keys, certs, and containers"
OUT="$("$BIN" scan "$DEMO")"
echo "$OUT" | grep -q "PRIVATE KEYS (7)"        || fail "want 7 private keys"
echo "$OUT" | grep -q "CERTIFICATES (3)"        || fail "want 3 certificates"
echo "$OUT" | grep -q "CERTIFICATE REQUESTS (1)" || fail "want 1 CSR"
echo "$OUT" | grep -q "CONTAINERS (2)"          || fail "want 2 containers"
echo "$OUT" | grep -q "encrypted aes256-ctr"    || fail "openssh cipher missing"
echo "$OUT" | grep -q "encrypted aes-256-cbc (pbkdf2)" || fail "pkcs8 cipher missing"
echo "$OUT" | grep -q "EXPIRED"                 || fail "expired cert not flagged"
echo "$OUT" | grep -q "0644 !"                  || fail "loose permissions not flagged"
echo "$OUT" | grep -q "deploy/.env:5"           || fail "embedded key line missing"

echo "5. JSON report is machine-readable and consistent"
JSON="$("$BIN" scan --format json "$DEMO")"
echo "$JSON" | grep -q '"tool": "keysweep"'     || fail "json envelope missing"
echo "$JSON" | grep -q '"schema_version": 1'    || fail "schema version missing"
echo "$JSON" | grep -q '"private_keys": 7'      || fail "json key count wrong"
echo "$JSON" | grep -q '"expired_certificates": 1' || fail "json expired count wrong"

echo "6. markdown report renders tables"
"$BIN" scan --format markdown "$DEMO" | grep -q '| Path | Algorithm |' \
  || fail "markdown table missing"

echo "7. exclude globs narrow the sweep"
"$BIN" scan --format json --exclude 'legacy/**' --exclude '*.p12' "$DEMO" \
  | grep -q '"private_keys": 4' || fail "--exclude not applied"

echo "8. check fails on the risky tree with evidence"
set +e
CHECK="$("$BIN" check "$DEMO")"
RC=$?
set -e
[ "$RC" -eq 1 ] || fail "check should exit 1, got $RC"
echo "$CHECK" | grep -q "plaintext-key"     || fail "plaintext breach missing"
echo "$CHECK" | grep -q "loose-permissions" || fail "perms breach missing"
echo "$CHECK" | grep -q "expired"           || fail "expired breach missing"
echo "$CHECK" | grep -q "FAIL"              || fail "verdict missing"

echo "9. check passes once the risky material is excluded"
"$BIN" check --allow-plaintext --ignore-perms \
  --exclude 'pki/old.crt' "$DEMO" | grep -q "PASS" \
  || fail "narrowed check should pass"

echo "10. usage errors exit 2"
set +e
"$BIN" scan --format yaml "$DEMO" >/dev/null 2>&1
[ $? -eq 2 ] || fail "bad --format should exit 2"
"$BIN" scan "$WORKDIR/absent" >/dev/null 2>&1
[ $? -eq 3 ] || fail "missing root should exit 3"
set -e

echo "SMOKE OK"
