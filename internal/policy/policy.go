// Package policy turns an inventory into a pass/fail verdict for the
// `keysweep check` gate. It is a pure function of (findings, now, rules),
// which makes every rule unit-testable without touching a filesystem.
package policy

import (
	"fmt"
	"time"

	"github.com/JaydenCJ/keysweep/internal/finding"
)

// Rules selects which conditions count as a breach.
type Rules struct {
	// AllowPlaintext disables the "unencrypted private key" rule.
	AllowPlaintext bool
	// IgnorePerms disables the loose-permissions rule.
	IgnorePerms bool
	// ExpiringDays fails certificates that expire within N days.
	// Expired certificates always fail regardless of this value.
	ExpiringDays int
	// MinRSABits fails RSA private keys smaller than this. 0 disables.
	MinRSABits int
}

// Breach is one policy violation, with the finding that caused it.
type Breach struct {
	Rule    string // plaintext-key, loose-permissions, expired, expiring, weak-rsa
	Path    string
	Line    int
	Message string
}

// Evaluate applies the rules to every finding and returns all breaches,
// in finding order (findings are already sorted by path).
func Evaluate(fs []finding.Finding, now time.Time, rules Rules) []Breach {
	var out []Breach
	add := func(rule string, f finding.Finding, msg string) {
		out = append(out, Breach{Rule: rule, Path: f.Path, Line: f.Line, Message: msg})
	}
	for _, f := range fs {
		switch f.Kind {
		case finding.KindPrivateKey:
			if !rules.AllowPlaintext && f.Protection == finding.ProtectionPlaintext {
				add("plaintext-key", f, "private key stored without a passphrase")
			}
			if !rules.IgnorePerms && f.LoosePerms() {
				add("loose-permissions", f,
					fmt.Sprintf("private key readable beyond owner (mode %04o)", f.Mode.Perm()))
			}
			if rules.MinRSABits > 0 && f.Algorithm == "rsa" && f.Bits > 0 && f.Bits < rules.MinRSABits {
				add("weak-rsa", f,
					fmt.Sprintf("rsa key is %d bits, below the %d-bit floor", f.Bits, rules.MinRSABits))
			}
		case finding.KindCertificate:
			switch {
			case f.Expired(now):
				add("expired", f,
					fmt.Sprintf("certificate %q expired %dd ago", f.Subject, -f.DaysLeft(now)))
			case rules.ExpiringDays > 0 && f.DaysLeft(now) < rules.ExpiringDays:
				add("expiring", f,
					fmt.Sprintf("certificate %q expires in %dd (window %dd)",
						f.Subject, f.DaysLeft(now), rules.ExpiringDays))
			}
		}
	}
	return out
}
