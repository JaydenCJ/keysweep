// Tests for the SSH wire-format reader shared by the OpenSSH and PuTTY
// parsers, including its behavior on hostile length prefixes.
package parse

import (
	"encoding/binary"
	"testing"
)

func blob(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		n := make([]byte, 4)
		binary.BigEndian.PutUint32(n, uint32(len(p)))
		out = append(out, n...)
		out = append(out, p...)
	}
	return out
}

func TestPublicBlobEd25519(t *testing.T) {
	info, err := parseSSHPublicBlob(blob([]byte("ssh-ed25519"), make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if info.Algorithm != "ed25519" || info.Bits != 256 {
		t.Fatalf("got %+v", info)
	}
}

func TestPublicBlobRSABitsFromModulus(t *testing.T) {
	// 256-byte modulus with high bit set → 2048-bit key.
	modulus := make([]byte, 256)
	modulus[0] = 0x80
	info, err := parseSSHPublicBlob(blob([]byte("ssh-rsa"), []byte{1, 0, 1}, modulus))
	if err != nil {
		t.Fatal(err)
	}
	if info.Algorithm != "rsa" || info.Bits != 2048 {
		t.Fatalf("got %+v", info)
	}
}

func TestPublicBlobECDSAP521(t *testing.T) {
	info, err := parseSSHPublicBlob(blob([]byte("ecdsa-sha2-nistp521"), []byte("nistp521"), make([]byte, 133)))
	if err != nil {
		t.Fatal(err)
	}
	if info.Curve != "nistp521" || info.Bits != 521 {
		t.Fatalf("got %+v", info)
	}
}

func TestPublicBlobUnknownTypeErrors(t *testing.T) {
	if _, err := parseSSHPublicBlob(blob([]byte("ssh-quantum"), []byte("x"))); err == nil {
		t.Fatal("unknown key types must error, not misreport")
	}
}

func TestHostileAndEmptyInputsError(t *testing.T) {
	// A length prefix of 0xFFFFFFFF pointing past the buffer must be an
	// error, never an allocation or a slice panic.
	hostile := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x41}
	if _, err := parseSSHPublicBlob(hostile); err == nil {
		t.Fatal("want truncation error")
	}
	r := &sshReader{buf: hostile}
	if _, err := r.bytes(); err == nil {
		t.Fatal("reader must reject out-of-range lengths")
	}
	if _, err := parseSSHPublicBlob(nil); err == nil {
		t.Fatal("empty blob must error")
	}
}
