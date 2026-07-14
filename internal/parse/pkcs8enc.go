package parse

import (
	"encoding/asn1"
	"errors"
)

// Encrypted PKCS#8 (`-----BEGIN ENCRYPTED PRIVATE KEY-----`) hides the key
// type, but the outer EncryptedPrivateKeyInfo structure names the cipher in
// the clear:
//
//	EncryptedPrivateKeyInfo ::= SEQUENCE {
//	    encryptionAlgorithm  AlgorithmIdentifier,
//	    encryptedData        OCTET STRING }
//
// For the modern PBES2 scheme the AlgorithmIdentifier's parameters nest a
// second AlgorithmIdentifier carrying the actual symmetric cipher OID.

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type encryptedPrivateKeyInfo struct {
	Algorithm     algorithmIdentifier
	EncryptedData []byte
}

type pbes2Params struct {
	KeyDerivationFunc algorithmIdentifier
	EncryptionScheme  algorithmIdentifier
}

var (
	oidPBES2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidScrypt = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11}
)

// cipherNames maps the symmetric-cipher and legacy-PBE OIDs seen in real
// encrypted PKCS#8 files to their OpenSSL-style names.
var cipherNames = map[string]string{
	"2.16.840.1.101.3.4.1.2":  "aes-128-cbc",
	"2.16.840.1.101.3.4.1.22": "aes-192-cbc",
	"2.16.840.1.101.3.4.1.42": "aes-256-cbc",
	"1.2.840.113549.3.7":      "des-ede3-cbc",
	"1.3.14.3.2.7":            "des-cbc",
	"1.2.840.113549.3.2":      "rc2-cbc",
	"1.2.840.113549.1.5.3":    "pbeWithMD5AndDES-CBC",
	"1.2.840.113549.1.5.10":   "pbeWithSHA1AndDES-CBC",
	"1.2.840.113549.1.12.1.3": "pbeWithSHA1And3-KeyTripleDES-CBC",
	"1.2.840.113549.1.12.1.6": "pbeWithSHA1And40BitRC2-CBC",
}

// parseEncryptedPKCS8Cipher returns the human-readable cipher (and KDF)
// protecting an encrypted PKCS#8 blob, e.g. "aes-256-cbc (pbkdf2)".
// It never needs the passphrase.
func parseEncryptedPKCS8Cipher(der []byte) (string, error) {
	var info encryptedPrivateKeyInfo
	if rest, err := asn1.Unmarshal(der, &info); err != nil {
		return "", err
	} else if len(rest) > 0 {
		return "", errors.New("trailing data after EncryptedPrivateKeyInfo")
	}
	if len(info.EncryptedData) == 0 {
		return "", errors.New("empty encryptedData")
	}

	oid := info.Algorithm.Algorithm
	if !oid.Equal(oidPBES2) {
		// Legacy PKCS#5 v1.5 / PKCS#12 PBE scheme: the outer OID is the cipher.
		if name, ok := cipherNames[oid.String()]; ok {
			return name, nil
		}
		return "oid:" + oid.String(), nil
	}

	var params pbes2Params
	if _, err := asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &params); err != nil {
		return "pbes2", nil // encrypted for sure; cipher detail unavailable
	}
	name, ok := cipherNames[params.EncryptionScheme.Algorithm.String()]
	if !ok {
		name = "oid:" + params.EncryptionScheme.Algorithm.String()
	}
	switch {
	case params.KeyDerivationFunc.Algorithm.Equal(oidPBKDF2):
		return name + " (pbkdf2)", nil
	case params.KeyDerivationFunc.Algorithm.Equal(oidScrypt):
		return name + " (scrypt)", nil
	default:
		return name, nil
	}
}
