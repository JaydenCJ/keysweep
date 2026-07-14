package parse

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"math/big"

	"github.com/JaydenCJ/keysweep/internal/finding"
)

// describeKey maps a parsed Go private-key value onto the inventory fields.
func describeKey(key any, f *finding.Finding) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		f.Algorithm = "rsa"
		f.Bits = k.N.BitLen()
	case *ecdsa.PrivateKey:
		f.Algorithm = "ecdsa"
		f.Curve = k.Curve.Params().Name
		f.Bits = k.Curve.Params().BitSize
	case ed25519.PrivateKey:
		f.Algorithm = "ed25519"
		f.Bits = 256
	case *ecdh.PrivateKey:
		// crypto/x509 returns *ecdh.PrivateKey for PKCS#8 X25519 keys.
		f.Algorithm = "x25519"
		f.Bits = 256
	}
}

// dsaKeyASN1 is the OpenSSL "traditional" DSA private key layout:
// SEQUENCE { version, p, q, g, y, x }. crypto/x509 cannot parse it, but the
// prime p — which fixes the key size — is one asn1.Unmarshal away.
type dsaKeyASN1 struct {
	Version int
	P, Q, G *big.Int
	Y, X    *big.Int
}

// parseDSAPrivateKey extracts the key size from a traditional DSA key.
func parseDSAPrivateKey(der []byte, f *finding.Finding) {
	var k dsaKeyASN1
	if _, err := asn1.Unmarshal(der, &k); err == nil && k.P != nil {
		f.Bits = k.P.BitLen()
	}
}

// describeCertificate fills the certificate-specific inventory fields.
func describeCertificate(cert *x509.Certificate, f *finding.Finding) {
	f.Kind = finding.KindCertificate
	f.Protection = finding.ProtectionNone
	f.Subject = nameString(cert.Subject.CommonName, cert.Subject.Organization, cert.DNSNames)
	f.Issuer = nameString(cert.Issuer.CommonName, cert.Issuer.Organization, nil)
	f.NotBefore = cert.NotBefore.UTC()
	f.NotAfter = cert.NotAfter.UTC()
	f.SelfSigned = string(cert.RawSubject) == string(cert.RawIssuer)
	f.IsCA = cert.IsCA
	describePublicKey(cert.PublicKey, f)
}

// describePublicKey records the algorithm and size of a certificate's or
// CSR's subject public key.
func describePublicKey(pub any, f *finding.Finding) {
	switch p := pub.(type) {
	case *rsa.PublicKey:
		f.Algorithm = "rsa"
		f.Bits = p.N.BitLen()
	case *ecdsa.PublicKey:
		f.Algorithm = "ecdsa"
		f.Curve = p.Curve.Params().Name
		f.Bits = p.Curve.Params().BitSize
	case ed25519.PublicKey:
		f.Algorithm = "ed25519"
		f.Bits = 256
	}
}

// nameString picks the most human-useful identifier from an X.509 name:
// CN, then the first Organization, then the first SAN.
func nameString(cn string, org []string, dnsNames []string) string {
	if cn != "" {
		return cn
	}
	if len(org) > 0 {
		return org[0]
	}
	if len(dnsNames) > 0 {
		return dnsNames[0]
	}
	return "(unnamed)"
}
