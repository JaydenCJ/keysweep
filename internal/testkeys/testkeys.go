// Package testkeys embeds the committed test fixtures: throwaway keys,
// certificates with pinned validity windows, and keystore stubs. Every
// fixture was generated purely for this repository's tests — none has
// ever protected anything. The package is imported only by tests and is
// never linked into the keysweep binary.
//
// Certificate fixtures pin these dates (UTC), which the tests rely on:
//
//	cert_ca.pem / cert_leaf.pem / fullchain.pem   2026-01-01 → 2036-01-01
//	cert_expired.pem                              2023-01-01 → 2025-01-01
//	cert_expiring_soon.pem                        2025-07-15 → 2026-07-15
package testkeys

import "embed"

//go:embed fixtures
var fixtures embed.FS

// Read returns a fixture's raw bytes by base name, e.g. "rsa2048_pkcs1.pem".
func Read(name string) []byte {
	b, err := fixtures.ReadFile("fixtures/" + name)
	if err != nil {
		panic("testkeys: unknown fixture " + name + ": " + err.Error())
	}
	return b
}

// Names lists every fixture base name, sorted (embed.FS guarantees order).
func Names() []string {
	entries, err := fixtures.ReadDir("fixtures")
	if err != nil {
		panic(err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}
