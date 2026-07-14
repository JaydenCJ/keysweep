// Tests for PEM extraction and classification: every mainstream private
// key encoding, encrypted variants, certificates, CSRs, and material
// embedded mid-file. Fixtures are committed throwaways (see testkeys).
package parse

import (
	"bytes"
	"testing"

	"github.com/JaydenCJ/keysweep/internal/finding"
	"github.com/JaydenCJ/keysweep/internal/testkeys"
)

// one asserts content yields exactly one finding and returns it.
func one(t *testing.T, content []byte) finding.Finding {
	t.Helper()
	fs := File(content)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(fs), fs)
	}
	return fs[0]
}

func TestPKCS1PlaintextRSAReportsBits(t *testing.T) {
	f := one(t, testkeys.Read("rsa2048_pkcs1.pem"))
	if f.Kind != finding.KindPrivateKey || f.Format != "pkcs1-pem" {
		t.Fatalf("wrong classification: %+v", f)
	}
	if f.Algorithm != "rsa" || f.Bits != 2048 {
		t.Fatalf("want rsa/2048, got %s/%d", f.Algorithm, f.Bits)
	}
	if f.Protection != finding.ProtectionPlaintext {
		t.Fatalf("want plaintext, got %s", f.Protection)
	}
}

func TestPKCS1EncryptedRSADetectsCipherFromDEKInfo(t *testing.T) {
	f := one(t, testkeys.Read("rsa2048_pkcs1_aes.pem"))
	if f.Protection != finding.ProtectionEncrypted {
		t.Fatalf("want encrypted, got %s", f.Protection)
	}
	if f.Cipher != "aes-256-cbc" {
		t.Fatalf("want aes-256-cbc from DEK-Info, got %q", f.Cipher)
	}
	// Bits are unknowable without the passphrase — must not be guessed.
	if f.Bits != 0 {
		t.Fatalf("encrypted key bits should be 0, got %d", f.Bits)
	}
	if f.Algorithm != "rsa" {
		t.Fatalf("algorithm is still knowable from the PEM type, got %q", f.Algorithm)
	}
}

func TestPKCS8EncryptedReportsPBES2Cipher(t *testing.T) {
	f := one(t, testkeys.Read("rsa2048_pkcs8_enc.pem"))
	if f.Protection != finding.ProtectionEncrypted {
		t.Fatalf("want encrypted, got %s", f.Protection)
	}
	if f.Cipher != "aes-256-cbc (pbkdf2)" {
		t.Fatalf("want cipher from the PBES2 envelope, got %q", f.Cipher)
	}
	// Encrypted PKCS#8 hides even the algorithm.
	if f.Algorithm != "" {
		t.Fatalf("algorithm should be unknown, got %q", f.Algorithm)
	}
}

func TestSEC1ECKeyReportsCurve(t *testing.T) {
	f := one(t, testkeys.Read("ec_p256_sec1.pem"))
	if f.Format != "sec1-pem" || f.Algorithm != "ecdsa" {
		t.Fatalf("got %+v", f)
	}
	if f.Curve != "P-256" || f.Bits != 256 {
		t.Fatalf("want P-256/256, got %s/%d", f.Curve, f.Bits)
	}
}

func TestPKCS8ModernAlgorithms(t *testing.T) {
	cases := []struct {
		fixture, algo, curve string
		bits                 int
	}{
		{"rsa2048_pkcs8.pem", "rsa", "", 2048},
		{"ec_p384_pkcs8.pem", "ecdsa", "P-384", 384},
		{"ed25519_pkcs8.pem", "ed25519", "", 256},
	}
	for _, c := range cases {
		f := one(t, testkeys.Read(c.fixture))
		if f.Format != "pkcs8-pem" || f.Algorithm != c.algo || f.Curve != c.curve || f.Bits != c.bits {
			t.Errorf("%s: got %+v", c.fixture, f)
		}
	}
}

func TestDSAKeys(t *testing.T) {
	// Traditional encoding: key size recovered from the ASN.1 prime p.
	f := one(t, testkeys.Read("dsa1024.pem"))
	if f.Format != "dsa-pem" || f.Algorithm != "dsa" || f.Bits != 1024 {
		t.Fatalf("got %+v", f)
	}
	// PKCS#8 DSA: crypto/x509 cannot parse it; the finding must survive
	// with honest unknowns instead of being dropped.
	f = one(t, testkeys.Read("dsa1024_pkcs8.pem"))
	if f.Kind != finding.KindPrivateKey || f.Format != "pkcs8-pem" {
		t.Fatalf("got %+v", f)
	}
	if f.Algorithm != "" || f.Bits != 0 {
		t.Fatalf("want unknown algorithm/bits, got %s/%d", f.Algorithm, f.Bits)
	}
}

func TestCertificateFieldsExtracted(t *testing.T) {
	f := one(t, testkeys.Read("cert_leaf.pem"))
	if f.Kind != finding.KindCertificate || f.Format != "x509-pem" {
		t.Fatalf("got %+v", f)
	}
	if f.Subject != "server.example.test" {
		t.Fatalf("subject: %q", f.Subject)
	}
	if f.Issuer != "Example Test Root CA" {
		t.Fatalf("issuer: %q", f.Issuer)
	}
	if f.SelfSigned {
		t.Fatal("CA-signed leaf must not be flagged self-signed")
	}
	if f.Algorithm != "rsa" || f.Bits != 2048 {
		t.Fatalf("public key: %s/%d", f.Algorithm, f.Bits)
	}
	if f.NotAfter.Year() != 2036 {
		t.Fatalf("NotAfter: %v", f.NotAfter)
	}
	if f.Protection != finding.ProtectionNone {
		t.Fatalf("certificates carry no secret, got %s", f.Protection)
	}
}

func TestSelfSignedCAFlags(t *testing.T) {
	f := one(t, testkeys.Read("cert_ca.pem"))
	if !f.SelfSigned || !f.IsCA {
		t.Fatalf("want self-signed CA, got %+v", f)
	}
	if f.Algorithm != "ecdsa" || f.Curve != "P-256" {
		t.Fatalf("got %s/%s", f.Algorithm, f.Curve)
	}
}

func TestMultiBlockFilesYieldEveryFinding(t *testing.T) {
	// fullchain.pem: leaf + CA, in order, with line numbers.
	fs := File(testkeys.Read("fullchain.pem"))
	if len(fs) != 2 {
		t.Fatalf("want leaf + CA, got %d findings", len(fs))
	}
	if fs[0].Line != 1 || fs[1].Line <= fs[0].Line {
		t.Fatalf("line numbers: %d, %d", fs[0].Line, fs[1].Line)
	}
	if fs[0].Subject != "server.example.test" || fs[1].Subject != "Example Test Root CA" {
		t.Fatalf("subjects: %q, %q", fs[0].Subject, fs[1].Subject)
	}
	// combined key+cert file: both kinds surface.
	fs = File(testkeys.Read("combined_key_and_cert.pem"))
	if len(fs) != 2 {
		t.Fatalf("want key + cert, got %d", len(fs))
	}
	if fs[0].Kind != finding.KindPrivateKey || fs[1].Kind != finding.KindCertificate {
		t.Fatalf("kinds: %s, %s", fs[0].Kind, fs[1].Kind)
	}
}

func TestCSRClassified(t *testing.T) {
	f := one(t, testkeys.Read("csr.pem"))
	if f.Kind != finding.KindCSR || f.Format != "csr-pem" {
		t.Fatalf("got %+v", f)
	}
	if f.Subject != "req.example.test" {
		t.Fatalf("subject: %q", f.Subject)
	}
	if f.Algorithm != "ecdsa" || f.Bits != 256 {
		t.Fatalf("public key: %s/%d", f.Algorithm, f.Bits)
	}
}

func TestKeyEmbeddedInConfigFileGetsLineNumber(t *testing.T) {
	f := one(t, testkeys.Read("embedded.env"))
	if f.Kind != finding.KindPrivateKey || f.Algorithm != "ed25519" {
		t.Fatalf("got %+v", f)
	}
	if f.Line != 5 {
		t.Fatalf("marker sits on line 5 of the fixture, got %d", f.Line)
	}
}

func TestIndentedKeyInsideYAMLIsFound(t *testing.T) {
	// Keys pasted into YAML values (kubeconfigs, compose files) are
	// indented, and the strict stdlib decoder rejects an indented END
	// line — this exercises the dedent fallback.
	var b bytes.Buffer
	b.WriteString("users:\n- name: dev\n  key: |\n")
	for _, line := range bytes.Split(testkeys.Read("ed25519_pkcs8.pem"), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		b.WriteString("    ")
		b.Write(line)
		b.WriteByte('\n')
	}
	f := one(t, b.Bytes())
	if f.Kind != finding.KindPrivateKey || f.Algorithm != "ed25519" {
		t.Fatalf("got %+v", f)
	}
	if f.Line != 4 {
		t.Fatalf("marker sits on line 4, got %d", f.Line)
	}
}

func TestNonMaterialBlocksAndProseAreIgnored(t *testing.T) {
	// Public keys carry no secret and are not inventory material.
	pub := []byte("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----\n")
	if fs := File(pub); len(fs) != 0 {
		t.Fatalf("public keys are not inventory material, got %+v", fs)
	}
	// A prose mention of the marker is not a block.
	prose := []byte("this file mentions -----BEGIN RSA PRIVATE KEY----- in prose\nand nothing else\n")
	if fs := File(prose); len(fs) != 0 {
		t.Fatalf("prose mention must not become a finding: %+v", fs)
	}
}

func TestUnknownPrivateKeyTypeStillCounts(t *testing.T) {
	exotic := []byte("-----BEGIN FANCY NEW PRIVATE KEY-----\nAAAA\n-----END FANCY NEW PRIVATE KEY-----\n")
	f := one(t, exotic)
	if f.Kind != finding.KindPrivateKey || f.Format != "pem" {
		t.Fatalf("got %+v", f)
	}
}

func TestGarbageToleranceAndCorruptPayloads(t *testing.T) {
	// Garbage around a valid block is tolerated; line number stays right.
	content := append([]byte("random prefix text\n\x00\x01\x02\n"), testkeys.Read("ec_p256_sec1.pem")...)
	content = append(content, []byte("\ntrailing noise")...)
	f := one(t, content)
	if f.Algorithm != "ecdsa" {
		t.Fatalf("got %+v", f)
	}
	if f.Line != 3 {
		t.Fatalf("want marker at line 3, got %d", f.Line)
	}
	// A structurally valid CERTIFICATE block with an unparseable payload
	// must be dropped, not misreported.
	lines := bytes.Split(testkeys.Read("cert_leaf.pem"), []byte("\n"))
	lines[1] = []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if fs := File(bytes.Join(lines, []byte("\n"))); len(fs) != 0 {
		t.Fatalf("unparseable certificate must be dropped, got %+v", fs)
	}
}
