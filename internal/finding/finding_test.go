// Tests for the shared data model helpers.
package finding

import (
	"io/fs"
	"testing"
	"time"
)

func TestLoosePermsBoundary(t *testing.T) {
	cases := []struct {
		mode uint32
		want bool
	}{
		{0o600, false},
		{0o400, false},
		{0o640, true},
		{0o604, true},
		{0o644, true},
		{0o700, false}, // execute bit for owner only is fine
	}
	for _, c := range cases {
		f := Finding{Mode: fs.FileMode(c.mode)}
		if got := f.LoosePerms(); got != c.want {
			t.Errorf("mode %04o: got %v, want %v", c.mode, got, c.want)
		}
	}
}

func TestExpiryHelpers(t *testing.T) {
	now := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	past := now.AddDate(-1, 0, 0)
	cert := Finding{Kind: KindCertificate, NotAfter: past}
	if !cert.Expired(now) {
		t.Fatal("past NotAfter must be expired")
	}
	// Expired only applies to certificates.
	key := Finding{Kind: KindPrivateKey, NotAfter: past}
	if key.Expired(now) {
		t.Fatal("keys have no expiry")
	}
	// DaysLeft truncates toward zero in both directions.
	f := Finding{Kind: KindCertificate, NotAfter: now.Add(36 * time.Hour)}
	if got := f.DaysLeft(now); got != 1 {
		t.Fatalf("36h → 1 day, got %d", got)
	}
	f.NotAfter = now.Add(-36 * time.Hour)
	if got := f.DaysLeft(now); got != -1 {
		t.Fatalf("-36h → -1 day, got %d", got)
	}
}

func TestSortIsDeterministicAcrossFields(t *testing.T) {
	fs := []Finding{
		{Path: "b", Line: 1},
		{Path: "a", Line: 9},
		{Path: "a", Line: 1, Format: "x509-pem"},
		{Path: "a", Line: 1, Format: "pkcs1-pem"},
	}
	Sort(fs)
	if fs[0].Format != "pkcs1-pem" || fs[1].Format != "x509-pem" {
		t.Fatalf("tie-break by format failed: %+v", fs)
	}
	if fs[2].Line != 9 || fs[3].Path != "b" {
		t.Fatalf("order: %+v", fs)
	}
}
