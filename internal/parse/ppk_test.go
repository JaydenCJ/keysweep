// Tests for the PuTTY .ppk parser (versions 2 and 3).
package parse

import (
	"strings"
	"testing"

	"github.com/JaydenCJ/keysweep/internal/finding"
	"github.com/JaydenCJ/keysweep/internal/testkeys"
)

func TestPPK3PlaintextEd25519(t *testing.T) {
	f := one(t, testkeys.Read("ppk3_ed25519.ppk"))
	if f.Format != "ppk3" || f.Algorithm != "ed25519" || f.Bits != 256 {
		t.Fatalf("got %+v", f)
	}
	if f.Protection != finding.ProtectionPlaintext {
		t.Fatalf("want plaintext, got %s", f.Protection)
	}
}

func TestPPK2EncryptedRSAReportsBitsAndCipher(t *testing.T) {
	f := one(t, testkeys.Read("ppk2_rsa_enc.ppk"))
	if f.Format != "ppk2" || f.Algorithm != "rsa" || f.Bits != 3072 {
		t.Fatalf("got %+v", f)
	}
	if f.Protection != finding.ProtectionEncrypted || f.Cipher != "aes256-cbc" {
		t.Fatalf("want encrypted aes256-cbc, got %s/%q", f.Protection, f.Cipher)
	}
}

func TestPPKUnsupportedVersionRejected(t *testing.T) {
	content := []byte("PuTTY-User-Key-File-9: ssh-rsa\r\nEncryption: none\r\n")
	if fs := File(content); len(fs) != 0 {
		t.Fatalf("unknown ppk version must not be guessed at: %+v", fs)
	}
}

func TestPPKDegradedInputsKeepHeaderFacts(t *testing.T) {
	// Header only, no public lines: algorithm and cipher still known.
	f := one(t, []byte("PuTTY-User-Key-File-3: ssh-ed25519\r\nEncryption: aes256-cbc\r\n"))
	if f.Algorithm != "ed25519" || f.Protection != finding.ProtectionEncrypted {
		t.Fatalf("got %+v", f)
	}
	// Truncated public blob: header facts must survive.
	content := strings.Replace(string(testkeys.Read("ppk3_ed25519.ppk")),
		"Public-Lines: 2", "Public-Lines: 1", 1)
	f = one(t, []byte(content))
	if f.Algorithm != "ed25519" || f.Format != "ppk3" {
		t.Fatalf("header facts must survive a bad public blob: %+v", f)
	}
	// Absurd Public-Lines count: rejected gracefully, no huge allocation.
	f = one(t, []byte("PuTTY-User-Key-File-2: ssh-rsa\r\nEncryption: none\r\nPublic-Lines: 999999\r\n"))
	if f.Algorithm != "rsa" {
		t.Fatalf("got %+v", f)
	}
}

func TestPPKParserNeverReadsPrivateLines(t *testing.T) {
	// A canary after Private-Lines proves the parser stops before secrets.
	content := string(testkeys.Read("ppk3_ed25519.ppk")) +
		"Encryption: none\r\n" // would flip protection if it were read
	raw := strings.Replace(content, "Encryption: none\r\nComment",
		"Encryption: aes256-cbc\r\nComment", 1)
	f := one(t, []byte(raw))
	if f.Protection != finding.ProtectionEncrypted {
		t.Fatalf("trailing lines after Private-Lines must be ignored: %+v", f)
	}
}
