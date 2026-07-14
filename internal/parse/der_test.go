// Tests for binary formats: bare DER keys and certificates, PKCS#12
// bundles, and Java keystores.
package parse

import (
	"testing"

	"github.com/JaydenCJ/keysweep/internal/finding"
	"github.com/JaydenCJ/keysweep/internal/testkeys"
)

func TestDERCertificate(t *testing.T) {
	f := one(t, testkeys.Read("cert_leaf.der"))
	if f.Kind != finding.KindCertificate || f.Format != "x509-der" {
		t.Fatalf("got %+v", f)
	}
	if f.Subject != "server.example.test" {
		t.Fatalf("subject: %q", f.Subject)
	}
	if f.Line != 0 {
		t.Fatalf("binary formats have no line number, got %d", f.Line)
	}
}

func TestDERPKCS8PlaintextKey(t *testing.T) {
	f := one(t, testkeys.Read("rsa2048_pkcs8.der"))
	if f.Format != "pkcs8-der" || f.Algorithm != "rsa" || f.Bits != 2048 {
		t.Fatalf("got %+v", f)
	}
	if f.Protection != finding.ProtectionPlaintext {
		t.Fatalf("want plaintext, got %s", f.Protection)
	}
}

func TestDEREncryptedPKCS8(t *testing.T) {
	f := one(t, testkeys.Read("rsa2048_pkcs8_enc.der"))
	if f.Format != "pkcs8-der" || f.Protection != finding.ProtectionEncrypted {
		t.Fatalf("got %+v", f)
	}
	if f.Cipher != "aes-256-cbc (pbkdf2)" {
		t.Fatalf("cipher: %q", f.Cipher)
	}
}

func TestPKCS12BundleDetectedAsContainer(t *testing.T) {
	f := one(t, testkeys.Read("bundle.p12"))
	if f.Kind != finding.KindContainer || f.Format != "pkcs12" {
		t.Fatalf("got %+v", f)
	}
	if f.Protection != finding.ProtectionPassword {
		t.Fatalf("pkcs12 is always password-wrapped, got %s", f.Protection)
	}
}

func TestJavaKeystoresDetectedByMagic(t *testing.T) {
	f := one(t, testkeys.Read("keystore.jks"))
	if f.Kind != finding.KindContainer || f.Format != "jks" {
		t.Fatalf("got %+v", f)
	}
	f = one(t, testkeys.Read("keystore.jceks"))
	if f.Format != "jceks" {
		t.Fatalf("got %+v", f)
	}
}

func TestBogusDERIsNotAFinding(t *testing.T) {
	// Plenty of binary files start with 0x30; the strict parsers must
	// reject them rather than fabricate inventory.
	junk := []byte{0x30, 0x82, 0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}
	if fs := File(junk); len(fs) != 0 {
		t.Fatalf("junk classified as %+v", fs)
	}
	der := testkeys.Read("cert_leaf.der")
	if fs := File(der[:len(der)/2]); len(fs) != 0 {
		t.Fatalf("truncated DER must yield nothing, got %+v", fs)
	}
}
