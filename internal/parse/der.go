package parse

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"

	"github.com/JaydenCJ/keysweep/internal/finding"
)

// Keystore magic numbers.
var (
	jksMagic   = []byte{0xFE, 0xED, 0xFE, 0xED} // Java KeyStore
	jceksMagic = []byte{0xCE, 0xCE, 0xCE, 0xCE} // Java JCEKS KeyStore
)

// parseKeystore recognizes Java keystores by magic number. Their entries
// are individually password-encrypted, so they are inventoried as
// password-protected containers.
func parseKeystore(content []byte) (finding.Finding, bool) {
	var format string
	switch {
	case bytes.HasPrefix(content, jksMagic):
		format = "jks"
	case bytes.HasPrefix(content, jceksMagic):
		format = "jceks"
	default:
		return finding.Finding{}, false
	}
	return finding.Finding{
		Kind:       finding.KindContainer,
		Format:     format,
		Protection: finding.ProtectionPassword,
	}, true
}

// pfxOuter matches the top of a PKCS#12 PFX: SEQUENCE { version INTEGER,
// authSafe ContentInfo, … }. Parsing stops at the ContentInfo OID — enough
// to identify the container without touching its encrypted payload.
type pfxOuter struct {
	Version  int
	AuthSafe struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
	}
	Rest asn1.RawValue `asn1:"optional"` // MacData
}

var oidPKCS7Data = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
var oidPKCS7SignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

// parsePKCS12 sniffs a DER blob for the PKCS#12 v3 envelope.
func parsePKCS12(der []byte) (finding.Finding, bool) {
	var pfx pfxOuter
	if _, err := asn1.Unmarshal(der, &pfx); err != nil {
		return finding.Finding{}, false
	}
	if pfx.Version != 3 {
		return finding.Finding{}, false
	}
	ct := pfx.AuthSafe.ContentType
	if !ct.Equal(oidPKCS7Data) && !ct.Equal(oidPKCS7SignedData) {
		return finding.Finding{}, false
	}
	return finding.Finding{
		Kind:       finding.KindContainer,
		Format:     "pkcs12",
		Protection: finding.ProtectionPassword,
	}, true
}

// scanDER tries the strict stdlib parsers against a raw DER blob, most
// specific first. Order matters: a certificate is also a valid-looking
// SEQUENCE, so it must be tried before the loose PKCS#12 sniff.
func scanDER(content []byte) (finding.Finding, bool) {
	if cert, err := x509.ParseCertificate(content); err == nil {
		f := finding.Finding{Format: "x509-der"}
		describeCertificate(cert, &f)
		return f, true
	}
	if key, err := x509.ParsePKCS8PrivateKey(content); err == nil {
		f := finding.Finding{
			Kind:       finding.KindPrivateKey,
			Format:     "pkcs8-der",
			Protection: finding.ProtectionPlaintext,
		}
		describeKey(key, &f)
		return f, true
	}
	if key, err := x509.ParsePKCS1PrivateKey(content); err == nil {
		return finding.Finding{
			Kind:       finding.KindPrivateKey,
			Format:     "pkcs1-der",
			Algorithm:  "rsa",
			Bits:       key.N.BitLen(),
			Protection: finding.ProtectionPlaintext,
		}, true
	}
	if key, err := x509.ParseECPrivateKey(content); err == nil {
		return finding.Finding{
			Kind:       finding.KindPrivateKey,
			Format:     "sec1-der",
			Algorithm:  "ecdsa",
			Curve:      key.Curve.Params().Name,
			Bits:       key.Curve.Params().BitSize,
			Protection: finding.ProtectionPlaintext,
		}, true
	}
	if cipher, err := parseEncryptedPKCS8Cipher(content); err == nil {
		return finding.Finding{
			Kind:       finding.KindPrivateKey,
			Format:     "pkcs8-der",
			Protection: finding.ProtectionEncrypted,
			Cipher:     cipher,
		}, true
	}
	return parsePKCS12(content)
}
