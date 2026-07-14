// Tests for the check-gate rules. The evaluator is a pure function, so
// each rule is exercised against hand-built findings and a pinned clock.
package policy

import (
	"io/fs"
	"testing"
	"time"

	"github.com/JaydenCJ/keysweep/internal/finding"
)

var now = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

func key(prot finding.Protection, mode fs.FileMode) finding.Finding {
	return finding.Finding{
		Path: "ssh/id_rsa", Kind: finding.KindPrivateKey,
		Algorithm: "rsa", Bits: 2048, Protection: prot, Mode: mode,
	}
}

func cert(notAfter time.Time) finding.Finding {
	return finding.Finding{
		Path: "tls/server.crt", Kind: finding.KindCertificate,
		Subject: "server.example.test", NotAfter: notAfter,
		Protection: finding.ProtectionNone,
	}
}

func rules(fs []finding.Finding, r Rules) []Breach {
	return Evaluate(fs, now, r)
}

func TestPlaintextKeyRule(t *testing.T) {
	b := rules([]finding.Finding{key(finding.ProtectionPlaintext, 0o600)}, Rules{})
	if len(b) != 1 || b[0].Rule != "plaintext-key" {
		t.Fatalf("plaintext must breach: %+v", b)
	}
	if b := rules([]finding.Finding{key(finding.ProtectionEncrypted, 0o600)}, Rules{}); len(b) != 0 {
		t.Fatalf("encrypted must pass: %+v", b)
	}
	b = rules([]finding.Finding{key(finding.ProtectionPlaintext, 0o600)}, Rules{AllowPlaintext: true})
	if len(b) != 0 {
		t.Fatalf("--allow-plaintext must disable the rule: %+v", b)
	}
}

func TestLoosePermissionsRule(t *testing.T) {
	// Fires even when the key itself is encrypted.
	b := rules([]finding.Finding{key(finding.ProtectionEncrypted, 0o644)}, Rules{})
	if len(b) != 1 || b[0].Rule != "loose-permissions" {
		t.Fatalf("got %+v", b)
	}
	b = rules([]finding.Finding{key(finding.ProtectionEncrypted, 0o644)}, Rules{IgnorePerms: true})
	if len(b) != 0 {
		t.Fatalf("--ignore-perms must disable the rule: %+v", b)
	}
}

func TestPlaintextAndLoosePermsAreTwoBreaches(t *testing.T) {
	b := rules([]finding.Finding{key(finding.ProtectionPlaintext, 0o644)}, Rules{})
	if len(b) != 2 {
		t.Fatalf("want both rules to fire, got %+v", b)
	}
}

func TestExpiredCertificateAlwaysBreaches(t *testing.T) {
	b := rules([]finding.Finding{cert(now.AddDate(0, -1, 0))}, Rules{})
	if len(b) != 1 || b[0].Rule != "expired" {
		t.Fatalf("got %+v", b)
	}
}

func TestExpiringWindowIsOptIn(t *testing.T) {
	soon := cert(now.AddDate(0, 0, 10))
	if b := rules([]finding.Finding{soon}, Rules{}); len(b) != 0 {
		t.Fatalf("no window set, got %+v", b)
	}
	b := rules([]finding.Finding{soon}, Rules{ExpiringDays: 30})
	if len(b) != 1 || b[0].Rule != "expiring" {
		t.Fatalf("got %+v", b)
	}
	// A certificate outside the window passes.
	far := cert(now.AddDate(5, 0, 0))
	if b := rules([]finding.Finding{far}, Rules{ExpiringDays: 30}); len(b) != 0 {
		t.Fatalf("got %+v", b)
	}
}

func TestMinRSABitsFloor(t *testing.T) {
	weak := key(finding.ProtectionEncrypted, 0o600)
	weak.Bits = 1024
	b := rules([]finding.Finding{weak}, Rules{MinRSABits: 2048})
	if len(b) != 1 || b[0].Rule != "weak-rsa" {
		t.Fatalf("got %+v", b)
	}
	// Keys whose size is unknowable (encrypted PKCS#8) must not be
	// punished for having Bits == 0.
	unknown := key(finding.ProtectionEncrypted, 0o600)
	unknown.Bits = 0
	if b := rules([]finding.Finding{unknown}, Rules{MinRSABits: 2048}); len(b) != 0 {
		t.Fatalf("got %+v", b)
	}
}

func TestContainersAndCSRsNeverBreach(t *testing.T) {
	fs := []finding.Finding{
		{Path: "b.p12", Kind: finding.KindContainer, Protection: finding.ProtectionPassword, Mode: 0o644},
		{Path: "r.csr", Kind: finding.KindCSR, Protection: finding.ProtectionNone, Mode: 0o644},
	}
	if b := rules(fs, Rules{ExpiringDays: 365, MinRSABits: 4096}); len(b) != 0 {
		t.Fatalf("got %+v", b)
	}
}

func TestBreachesPreserveFindingOrder(t *testing.T) {
	a := key(finding.ProtectionPlaintext, 0o600)
	a.Path = "a.key"
	z := key(finding.ProtectionPlaintext, 0o600)
	z.Path = "z.key"
	b := rules([]finding.Finding{a, z}, Rules{})
	if len(b) != 2 || b[0].Path != "a.key" || b[1].Path != "z.key" {
		t.Fatalf("got %+v", b)
	}
}
