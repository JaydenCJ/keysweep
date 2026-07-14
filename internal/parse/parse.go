// Package parse identifies cryptographic material inside raw file
// contents: PEM blocks (wherever they are embedded), OpenSSH private
// keys, PuTTY .ppk files, bare DER keys and certificates, PKCS#12
// bundles, and Java keystores.
//
// Everything here is a pure function of the input bytes: no clock, no
// filesystem, no network — which is what keeps the whole suite
// deterministic and fast. Nothing in this package ever decrypts anything;
// protection state is read from headers and envelopes that are public by
// design.
package parse

import (
	"bytes"

	"github.com/JaydenCJ/keysweep/internal/finding"
)

// File extracts every finding from one file's contents. The caller fills
// in Path and Mode; parse fills in everything intrinsic to the bytes.
func File(content []byte) []finding.Finding {
	if len(content) == 0 {
		return nil
	}

	// Whole-file binary and single-document text formats first.
	if f, ok := parseKeystore(content); ok {
		return []finding.Finding{f}
	}
	if bytes.HasPrefix(content, ppkPrefix) {
		if f, err := parsePPK(content); err == nil {
			return []finding.Finding{f}
		}
		return nil
	}

	// PEM blocks may appear anywhere: certificates bundled with keys,
	// keys pasted into .env or YAML files, chains of several blocks.
	if bytes.Contains(content, pemMarker) {
		return scanPEM(content)
	}

	// Raw DER always begins with an ASN.1 SEQUENCE tag (0x30). The strict
	// parsers reject unrelated binary files that merely share the byte.
	if content[0] == 0x30 {
		if f, ok := scanDER(content); ok {
			return []finding.Finding{f}
		}
	}
	return nil
}
