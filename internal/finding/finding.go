// Package finding defines the data model shared by every keysweep layer:
// one Finding per piece of cryptographic material discovered on disk.
package finding

import (
	"io/fs"
	"sort"
	"time"
)

// Kind classifies what a piece of material is.
type Kind string

const (
	// KindPrivateKey is any private key, in any encoding.
	KindPrivateKey Kind = "private-key"
	// KindCertificate is an X.509 certificate.
	KindCertificate Kind = "certificate"
	// KindCSR is a PKCS#10 certificate signing request.
	KindCSR Kind = "certificate-request"
	// KindContainer is a keystore that bundles keys and certificates
	// behind a password (PKCS#12, JKS, JCEKS). Its contents cannot be
	// enumerated without the password, so it is inventoried as a unit.
	KindContainer Kind = "container"
)

// Protection describes whether the material is usable without a secret.
type Protection string

const (
	// ProtectionPlaintext means anyone who can read the file owns the key.
	ProtectionPlaintext Protection = "plaintext"
	// ProtectionEncrypted means a passphrase is required to use the key.
	ProtectionEncrypted Protection = "encrypted"
	// ProtectionPassword means the format is always password-wrapped
	// (PKCS#12, JKS) — though the password may be empty.
	ProtectionPassword Protection = "password"
	// ProtectionNone applies to material that carries no secret at all
	// (certificates, CSRs).
	ProtectionNone Protection = "none"
)

// Finding is one discovered piece of cryptographic material. A single file
// can yield several findings (e.g. fullchain.pem, combined key+cert files).
type Finding struct {
	// Path is the file path relative to the scan root, slash-separated.
	Path string
	// Line is the 1-based line of the PEM/PPK marker inside the file;
	// 0 for whole-file binary formats (DER, PKCS#12, JKS).
	Line int

	Kind       Kind
	Format     string // pkcs1-pem, pkcs8-pem, sec1-pem, dsa-pem, openssh, ppk2, ppk3, x509-pem, csr-pem, pkcs1-der, pkcs8-der, sec1-der, x509-der, pkcs12, jks, jceks
	Algorithm  string // rsa, ecdsa, ed25519, dsa, x25519, "" when unknowable
	Curve      string // P-256, P-384, P-521, nistp256… for ECDSA keys
	Bits       int    // modulus/field size; 0 when unknowable without a secret
	Protection Protection
	Cipher     string // aes-256-cbc, aes256-ctr, des-ede3-cbc… when encrypted

	// Certificate-only fields.
	Subject    string
	Issuer     string
	NotBefore  time.Time
	NotAfter   time.Time
	SelfSigned bool
	IsCA       bool

	// File metadata, filled in by the scanner.
	Mode fs.FileMode
}

// LoosePerms reports whether the file grants any permission to group or
// other — the same test OpenSSH applies before refusing an identity file.
// Only meaningful for private keys and containers.
func (f Finding) LoosePerms() bool {
	return f.Mode.Perm()&0o077 != 0
}

// Expired reports whether a certificate finding is past NotAfter at `now`.
func (f Finding) Expired(now time.Time) bool {
	return f.Kind == KindCertificate && now.After(f.NotAfter)
}

// DaysLeft returns whole days until NotAfter (negative if expired).
func (f Finding) DaysLeft(now time.Time) int {
	return int(f.NotAfter.Sub(now).Hours() / 24)
}

// Sort orders findings by path, then line, then format, so every report is
// byte-identical for identical input trees.
func Sort(fs []Finding) {
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].Path != fs[j].Path {
			return fs[i].Path < fs[j].Path
		}
		if fs[i].Line != fs[j].Line {
			return fs[i].Line < fs[j].Line
		}
		return fs[i].Format < fs[j].Format
	})
}
