package parse

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/JaydenCJ/keysweep/internal/finding"
)

// opensshMagic starts the binary payload of every openssh-key-v1 file
// (the format ssh-keygen has produced by default since OpenSSH 7.8).
var opensshMagic = []byte("openssh-key-v1\x00")

// parseOpenSSH decodes the binary payload of a `-----BEGIN OPENSSH PRIVATE
// KEY-----` block. The container stores the cipher name and every public
// key in the clear, so algorithm, size, and encryption state are all
// recoverable without the passphrase.
func parseOpenSSH(payload []byte) (finding.Finding, error) {
	if !bytes.HasPrefix(payload, opensshMagic) {
		return finding.Finding{}, errors.New("missing openssh-key-v1 magic")
	}
	r := &sshReader{buf: payload[len(opensshMagic):]}

	cipher, err := r.str()
	if err != nil {
		return finding.Finding{}, err
	}
	if _, err := r.str(); err != nil { // kdfname (bcrypt or none)
		return finding.Finding{}, err
	}
	if _, err := r.bytes(); err != nil { // kdfoptions (salt + rounds)
		return finding.Finding{}, err
	}
	nkeys, err := r.uint32()
	if err != nil {
		return finding.Finding{}, err
	}
	if nkeys == 0 || nkeys > 64 {
		return finding.Finding{}, fmt.Errorf("implausible key count %d", nkeys)
	}
	// The file carries nkeys public blobs; in practice nkeys is always 1.
	pubBlob, err := r.bytes()
	if err != nil {
		return finding.Finding{}, err
	}
	info, err := parseSSHPublicBlob(pubBlob)
	if err != nil {
		return finding.Finding{}, err
	}

	f := finding.Finding{
		Kind:      finding.KindPrivateKey,
		Format:    "openssh",
		Algorithm: info.Algorithm,
		Curve:     info.Curve,
		Bits:      info.Bits,
	}
	if cipher == "none" || cipher == "" {
		f.Protection = finding.ProtectionPlaintext
	} else {
		f.Protection = finding.ProtectionEncrypted
		f.Cipher = cipher
	}
	return f, nil
}
