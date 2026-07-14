package parse

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/JaydenCJ/keysweep/internal/finding"
)

// ppkPrefix opens every PuTTY private key file, versions 1 through 3.
var ppkPrefix = []byte("PuTTY-User-Key-File-")

// parsePPK reads a PuTTY .ppk file. The header names the algorithm and the
// encryption cipher, and Public-Lines carries the standard SSH public blob
// in the clear, so the key size is available even for encrypted keys.
func parsePPK(content []byte) (finding.Finding, error) {
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	if !sc.Scan() {
		return finding.Finding{}, errors.New("empty ppk file")
	}
	first := strings.TrimRight(sc.Text(), "\r")
	rest, ok := strings.CutPrefix(first, string(ppkPrefix))
	if !ok {
		return finding.Finding{}, errors.New("missing PuTTY-User-Key-File header")
	}
	ver, keyType, ok := strings.Cut(rest, ": ")
	if !ok {
		return finding.Finding{}, errors.New("malformed PuTTY-User-Key-File header")
	}
	if ver != "1" && ver != "2" && ver != "3" {
		return finding.Finding{}, fmt.Errorf("unsupported ppk version %q", ver)
	}

	f := finding.Finding{
		Kind:       finding.KindPrivateKey,
		Format:     "ppk" + ver,
		Protection: finding.ProtectionPlaintext,
	}
	switch {
	case keyType == "ssh-rsa":
		f.Algorithm = "rsa"
	case keyType == "ssh-dss":
		f.Algorithm = "dsa"
	case keyType == "ssh-ed25519":
		f.Algorithm = "ed25519"
		f.Bits = 256
	case strings.HasPrefix(keyType, "ecdsa-sha2-"):
		f.Algorithm = "ecdsa"
	}

	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		key, value, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		switch key {
		case "Encryption":
			if value != "none" && value != "" {
				f.Protection = finding.ProtectionEncrypted
				f.Cipher = value
			}
		case "Public-Lines":
			n, err := strconv.Atoi(value)
			if err != nil || n < 1 || n > 4096 {
				return f, nil // header already yielded the essentials
			}
			var b64 strings.Builder
			for i := 0; i < n && sc.Scan(); i++ {
				b64.WriteString(strings.TrimRight(sc.Text(), "\r"))
			}
			blob, err := base64.StdEncoding.DecodeString(b64.String())
			if err != nil {
				continue
			}
			if info, err := parseSSHPublicBlob(blob); err == nil {
				f.Algorithm = info.Algorithm
				f.Curve = info.Curve
				f.Bits = info.Bits
			}
		case "Private-Lines":
			// Everything after the public blob is either ciphertext or
			// secrets; the inventory never reads it.
			return f, nil
		}
	}
	return f, nil
}
