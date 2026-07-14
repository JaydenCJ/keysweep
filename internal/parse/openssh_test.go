// Tests for the openssh-key-v1 container parser. The critical property:
// cipher name and public key material live in the clear, so keysweep can
// report algorithm, size, and encryption state without any passphrase.
package parse

import (
	"encoding/binary"
	"encoding/pem"
	"testing"

	"github.com/JaydenCJ/keysweep/internal/finding"
	"github.com/JaydenCJ/keysweep/internal/testkeys"
)

func TestOpenSSHPlaintextEd25519(t *testing.T) {
	f := one(t, testkeys.Read("openssh_ed25519.key"))
	if f.Format != "openssh" || f.Algorithm != "ed25519" || f.Bits != 256 {
		t.Fatalf("got %+v", f)
	}
	if f.Protection != finding.ProtectionPlaintext || f.Cipher != "" {
		t.Fatalf("want plaintext, got %s/%q", f.Protection, f.Cipher)
	}
}

func TestOpenSSHEncryptedRSAStillReportsBits(t *testing.T) {
	f := one(t, testkeys.Read("openssh_rsa3072_enc.key"))
	if f.Algorithm != "rsa" || f.Bits != 3072 {
		t.Fatalf("public blob is cleartext even when encrypted; got %s/%d", f.Algorithm, f.Bits)
	}
	if f.Protection != finding.ProtectionEncrypted || f.Cipher != "aes256-ctr" {
		t.Fatalf("want encrypted aes256-ctr, got %s/%q", f.Protection, f.Cipher)
	}
}

func TestOpenSSHECDSACurveDetected(t *testing.T) {
	f := one(t, testkeys.Read("openssh_ecdsa256.key"))
	if f.Algorithm != "ecdsa" || f.Curve != "nistp256" || f.Bits != 256 {
		t.Fatalf("got %+v", f)
	}
}

// rebuildPayload extracts the binary payload of an openssh PEM fixture so
// corruption tests can operate below the base64 layer.
func opensshPayload(t *testing.T, name string) []byte {
	t.Helper()
	block, _ := pem.Decode(testkeys.Read(name))
	if block == nil {
		t.Fatal("fixture is not PEM")
	}
	return block.Bytes
}

func TestOpenSSHRejectsCorruptPayloads(t *testing.T) {
	// Corrupted magic.
	payload := opensshPayload(t, "openssh_ed25519.key")
	payload[0] ^= 0xFF
	if _, err := parseOpenSSH(payload); err == nil {
		t.Fatal("corrupted magic must be rejected")
	}
	// Truncation at several depths must error, never panic.
	payload = opensshPayload(t, "openssh_ed25519.key")
	for _, cut := range []int{16, 20, 30} {
		if _, err := parseOpenSSH(payload[:cut]); err == nil {
			t.Fatalf("truncation at %d bytes must error", cut)
		}
	}
	// Implausible key count: locate nkeys (magic + 3 strings) and inflate it.
	off := len(opensshMagic)
	for i := 0; i < 3; i++ {
		n := binary.BigEndian.Uint32(payload[off:])
		off += 4 + int(n)
	}
	binary.BigEndian.PutUint32(payload[off:], 9999)
	if _, err := parseOpenSSH(payload); err == nil {
		t.Fatal("9999 keys in one file is not a real key file")
	}
}

func TestOpenSSHUnparseableFallsBackToGenericFinding(t *testing.T) {
	// A PEM block typed OPENSSH PRIVATE KEY with junk inside must still be
	// counted as a private key — dropping it would understate the inventory.
	junk := pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: []byte("not-a-key")})
	f := one(t, junk)
	if f.Kind != finding.KindPrivateKey || f.Format != "openssh" {
		t.Fatalf("got %+v", f)
	}
	if f.Bits != 0 || f.Algorithm != "" {
		t.Fatalf("unknowns must stay unknown: %+v", f)
	}
}
