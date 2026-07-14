// Package report renders scan results as aligned text, stable JSON, or
// Markdown. All renderers are pure functions of (result, now), so a given
// tree always produces byte-identical output.
package report

import (
	"time"

	"github.com/JaydenCJ/keysweep/internal/finding"
)

// Summary aggregates a scan into the numbers people actually ask about.
type Summary struct {
	PrivateKeys   int
	PlaintextKeys int
	EncryptedKeys int
	LooseKeyPerms int

	Certificates int
	Expired      int
	ExpiringSoon int // within the --expiring window, not yet expired

	CSRs       int
	Containers int
}

// Summarize computes the Summary at a given instant. expiringDays is the
// look-ahead window for "expiring soon"; 0 disables that bucket.
func Summarize(fs []finding.Finding, now time.Time, expiringDays int) Summary {
	var s Summary
	for _, f := range fs {
		switch f.Kind {
		case finding.KindPrivateKey:
			s.PrivateKeys++
			switch f.Protection {
			case finding.ProtectionPlaintext:
				s.PlaintextKeys++
			case finding.ProtectionEncrypted:
				s.EncryptedKeys++
			}
			if f.LoosePerms() {
				s.LooseKeyPerms++
			}
		case finding.KindCertificate:
			s.Certificates++
			if f.Expired(now) {
				s.Expired++
			} else if expiringDays > 0 && f.DaysLeft(now) < expiringDays {
				s.ExpiringSoon++
			}
		case finding.KindCSR:
			s.CSRs++
		case finding.KindContainer:
			s.Containers++
		}
	}
	return s
}
