package parse

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"strings"

	"github.com/JaydenCJ/keysweep/internal/finding"
)

var pemMarker = []byte("-----BEGIN ")

// scanPEM extracts and classifies every PEM block in content, wherever it
// sits — a bare .pem file, a combined key+chain bundle, or a key pasted
// into a config file. Each finding records the 1-based line of its
// `-----BEGIN` marker so reports can point at embedded material precisely.
func scanPEM(content []byte) []finding.Finding {
	var out []finding.Finding
	rest := content
	base := 0 // offset of rest within content
	for {
		idx := bytes.Index(rest, pemMarker)
		if idx < 0 {
			return out
		}
		block, after := pem.Decode(rest[idx:])
		if block == nil {
			// Not decodable in place. Keys pasted into YAML or other config
			// files are usually indented, which the strict stdlib decoder
			// rejects; retry against a dedented copy of the block's lines.
			if f, consumed, ok := decodeIndented(rest[idx:]); ok {
				f.Line = 1 + bytes.Count(content[:base+idx], []byte("\n"))
				out = append(out, f)
				base += idx + consumed
				rest = rest[idx+consumed:]
				continue
			}
			// A stray marker without a decodable block; step past it.
			base += idx + len(pemMarker)
			rest = rest[idx+len(pemMarker):]
			continue
		}
		if f, ok := classifyPEM(block); ok {
			f.Line = 1 + bytes.Count(content[:base+idx], []byte("\n"))
			out = append(out, f)
		}
		consumed := len(rest) - idx - len(after)
		base += idx + consumed
		rest = after
	}
}

// decodeIndented handles a PEM block whose lines carry a leading-whitespace
// prefix (a key indented inside a YAML value or an INI/HCL heredoc). src
// starts at the `-----BEGIN` marker; the bytes up to the end of the matching
// `-----END …` line are copied with per-line leading whitespace stripped and
// re-decoded strictly. Returns the classified finding and how many bytes of
// src the block spans, or ok=false if no complete block is there.
func decodeIndented(src []byte) (finding.Finding, int, bool) {
	endIdx := bytes.Index(src, []byte("-----END "))
	if endIdx < 0 {
		return finding.Finding{}, 0, false
	}
	consumed := endIdx
	if nl := bytes.IndexByte(src[endIdx:], '\n'); nl >= 0 {
		consumed = endIdx + nl + 1
	} else {
		consumed = len(src)
	}
	lines := bytes.Split(src[:consumed], []byte("\n"))
	for i, line := range lines {
		lines[i] = bytes.TrimLeft(line, " \t")
	}
	dedented := append(bytes.Join(lines, []byte("\n")), '\n')
	block, _ := pem.Decode(dedented)
	if block == nil {
		return finding.Finding{}, 0, false
	}
	f, ok := classifyPEM(block)
	if !ok {
		return finding.Finding{}, 0, false
	}
	return f, consumed, true
}

// legacyEncrypted reports OpenSSL "traditional" PEM encryption, signalled
// by RFC 1421 headers (`Proc-Type: 4,ENCRYPTED` + `DEK-Info: <cipher>,IV`).
func legacyEncrypted(block *pem.Block) (cipher string, encrypted bool) {
	if !strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
		return "", false
	}
	cipher = block.Headers["DEK-Info"]
	if i := strings.IndexByte(cipher, ','); i >= 0 {
		cipher = cipher[:i]
	}
	return strings.ToLower(cipher), true
}

// classifyPEM turns one PEM block into a finding. It returns ok=false for
// block types that carry no private material and no identity (public keys,
// DH parameters, session tickets…).
func classifyPEM(block *pem.Block) (finding.Finding, bool) {
	f := finding.Finding{Kind: finding.KindPrivateKey, Protection: finding.ProtectionPlaintext}
	if cipher, enc := legacyEncrypted(block); enc {
		f.Protection = finding.ProtectionEncrypted
		f.Cipher = cipher
	}
	plaintext := f.Protection == finding.ProtectionPlaintext

	switch block.Type {
	case "RSA PRIVATE KEY":
		f.Format = "pkcs1-pem"
		f.Algorithm = "rsa"
		if plaintext {
			if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
				f.Bits = key.N.BitLen()
			}
		}
		return f, true

	case "PRIVATE KEY":
		f.Format = "pkcs8-pem"
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			describeKey(key, &f)
		}
		return f, true

	case "ENCRYPTED PRIVATE KEY":
		f.Format = "pkcs8-pem"
		f.Protection = finding.ProtectionEncrypted
		if cipher, err := parseEncryptedPKCS8Cipher(block.Bytes); err == nil {
			f.Cipher = cipher
		}
		return f, true

	case "EC PRIVATE KEY":
		f.Format = "sec1-pem"
		f.Algorithm = "ecdsa"
		if plaintext {
			if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				f.Curve = key.Curve.Params().Name
				f.Bits = key.Curve.Params().BitSize
			}
		}
		return f, true

	case "DSA PRIVATE KEY":
		f.Format = "dsa-pem"
		f.Algorithm = "dsa"
		if plaintext {
			parseDSAPrivateKey(block.Bytes, &f)
		}
		return f, true

	case "OPENSSH PRIVATE KEY":
		if osh, err := parseOpenSSH(block.Bytes); err == nil {
			return osh, true
		}
		f.Format = "openssh"
		return f, true

	case "CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return finding.Finding{}, false
		}
		f.Format = "x509-pem"
		describeCertificate(cert, &f)
		return f, true

	case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST":
		req, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return finding.Finding{}, false
		}
		f.Kind = finding.KindCSR
		f.Format = "csr-pem"
		f.Protection = finding.ProtectionNone
		f.Subject = nameString(req.Subject.CommonName, req.Subject.Organization, req.DNSNames)
		describePublicKey(req.PublicKey, &f)
		return f, true

	default:
		// Any other "… PRIVATE KEY" flavor still counts as key material,
		// even if we cannot introspect it.
		if strings.HasSuffix(block.Type, "PRIVATE KEY") {
			f.Format = "pem"
			return f, true
		}
		return finding.Finding{}, false
	}
}
