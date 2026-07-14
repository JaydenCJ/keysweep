package parse

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// sshReader walks the SSH wire format (RFC 4251 §5): a stream of
// uint32-length-prefixed strings. It underlies both the openssh-key-v1
// container and the public-key blobs shared by OpenSSH and PuTTY files.
type sshReader struct {
	buf []byte
	off int
}

var errSSHTruncated = errors.New("truncated ssh wire data")

func (r *sshReader) uint32() (uint32, error) {
	if r.off+4 > len(r.buf) {
		return 0, errSSHTruncated
	}
	v := binary.BigEndian.Uint32(r.buf[r.off:])
	r.off += 4
	return v, nil
}

func (r *sshReader) bytes() ([]byte, error) {
	n, err := r.uint32()
	if err != nil {
		return nil, err
	}
	if uint64(r.off)+uint64(n) > uint64(len(r.buf)) {
		return nil, errSSHTruncated
	}
	b := r.buf[r.off : r.off+int(n)]
	r.off += int(n)
	return b, nil
}

func (r *sshReader) str() (string, error) {
	b, err := r.bytes()
	return string(b), err
}

// mpintBits returns the bit length of an SSH mpint field.
func (r *sshReader) mpintBits() (int, error) {
	b, err := r.bytes()
	if err != nil {
		return 0, err
	}
	return new(big.Int).SetBytes(b).BitLen(), nil
}

// pubKeyInfo describes the algorithm extracted from an SSH public-key blob.
type pubKeyInfo struct {
	Algorithm string // rsa, ecdsa, ed25519, dsa
	Curve     string // nistp256… for ecdsa
	Bits      int
}

// parseSSHPublicBlob decodes a raw SSH public-key blob (the binary payload
// of an authorized_keys entry) into algorithm, curve, and key size. The
// blob is stored in the clear even inside passphrase-protected private key
// files, which is what lets keysweep report the size of encrypted keys.
func parseSSHPublicBlob(blob []byte) (pubKeyInfo, error) {
	r := &sshReader{buf: blob}
	keyType, err := r.str()
	if err != nil {
		return pubKeyInfo{}, err
	}
	switch {
	case keyType == "ssh-rsa":
		if _, err := r.bytes(); err != nil { // public exponent e
			return pubKeyInfo{}, err
		}
		bits, err := r.mpintBits() // modulus n
		if err != nil {
			return pubKeyInfo{}, err
		}
		return pubKeyInfo{Algorithm: "rsa", Bits: bits}, nil
	case keyType == "ssh-ed25519":
		if _, err := r.bytes(); err != nil {
			return pubKeyInfo{}, err
		}
		return pubKeyInfo{Algorithm: "ed25519", Bits: 256}, nil
	case keyType == "ssh-dss":
		bits, err := r.mpintBits() // prime p
		if err != nil {
			return pubKeyInfo{}, err
		}
		return pubKeyInfo{Algorithm: "dsa", Bits: bits}, nil
	case strings.HasPrefix(keyType, "ecdsa-sha2-"):
		curve, err := r.str()
		if err != nil {
			return pubKeyInfo{}, err
		}
		bits, ok := nistCurveBits[curve]
		if !ok {
			return pubKeyInfo{Algorithm: "ecdsa", Curve: curve}, nil
		}
		return pubKeyInfo{Algorithm: "ecdsa", Curve: curve, Bits: bits}, nil
	case strings.HasPrefix(keyType, "sk-ssh-ed25519"):
		return pubKeyInfo{Algorithm: "ed25519", Bits: 256}, nil
	case strings.HasPrefix(keyType, "sk-ecdsa-sha2-nistp256"):
		return pubKeyInfo{Algorithm: "ecdsa", Curve: "nistp256", Bits: 256}, nil
	default:
		return pubKeyInfo{}, fmt.Errorf("unrecognized ssh key type %q", keyType)
	}
}

var nistCurveBits = map[string]int{
	"nistp256": 256,
	"nistp384": 384,
	"nistp521": 521,
}
