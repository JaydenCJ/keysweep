package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/JaydenCJ/keysweep/internal/finding"
	"github.com/JaydenCJ/keysweep/internal/sweep"
)

// Options tunes rendering; the zero value is sensible.
type Options struct {
	// ExpiringDays marks certificates expiring within N days. 0 disables.
	ExpiringDays int
}

// Text renders the human-readable report.
func Text(res sweep.Result, now time.Time, opts Options) string {
	var b strings.Builder
	fmt.Fprintf(&b, "keysweep scan — %s\n", res.Root)
	fmt.Fprintf(&b, "files scanned: %d · findings: %d", res.FilesScanned, len(res.Findings))
	if res.FilesSkipped > 0 {
		fmt.Fprintf(&b, " · skipped: %d", res.FilesSkipped)
	}
	b.WriteString("\n")

	if len(res.Findings) == 0 {
		b.WriteString("\nno cryptographic material found\n")
		return b.String()
	}

	keys := ofKind(res.Findings, finding.KindPrivateKey)
	certs := ofKind(res.Findings, finding.KindCertificate)
	csrs := ofKind(res.Findings, finding.KindCSR)
	containers := ofKind(res.Findings, finding.KindContainer)

	if len(keys) > 0 {
		fmt.Fprintf(&b, "\nPRIVATE KEYS (%d)\n", len(keys))
		rows := [][]string{{"PATH", "ALGO", "BITS", "FORMAT", "PROTECTION", "PERMS"}}
		for _, f := range keys {
			rows = append(rows, []string{
				pathAt(f), algo(f), bits(f), f.Format, protection(f), perms(f),
			})
		}
		table(&b, rows)
	}

	if len(certs) > 0 {
		fmt.Fprintf(&b, "\nCERTIFICATES (%d)\n", len(certs))
		rows := [][]string{{"PATH", "SUBJECT", "ALGO", "BITS", "NOT AFTER", "STATUS"}}
		for _, f := range certs {
			rows = append(rows, []string{
				pathAt(f), f.Subject, algo(f), bits(f),
				f.NotAfter.Format("2006-01-02"), certStatus(f, now, opts.ExpiringDays),
			})
		}
		table(&b, rows)
	}

	if len(csrs) > 0 {
		fmt.Fprintf(&b, "\nCERTIFICATE REQUESTS (%d)\n", len(csrs))
		rows := [][]string{{"PATH", "SUBJECT", "ALGO", "BITS"}}
		for _, f := range csrs {
			rows = append(rows, []string{pathAt(f), f.Subject, algo(f), bits(f)})
		}
		table(&b, rows)
	}

	if len(containers) > 0 {
		fmt.Fprintf(&b, "\nCONTAINERS (%d)\n", len(containers))
		rows := [][]string{{"PATH", "FORMAT", "PROTECTION"}}
		for _, f := range containers {
			rows = append(rows, []string{pathAt(f), f.Format, string(f.Protection)})
		}
		table(&b, rows)
	}

	s := Summarize(res.Findings, now, opts.ExpiringDays)
	b.WriteString("\nSUMMARY\n")
	if s.PrivateKeys > 0 {
		line := fmt.Sprintf("  private keys : %d (%d plaintext, %d encrypted", s.PrivateKeys, s.PlaintextKeys, s.EncryptedKeys)
		if s.LooseKeyPerms > 0 {
			line += fmt.Sprintf("; %d with loose permissions", s.LooseKeyPerms)
		}
		b.WriteString(line + ")\n")
	}
	if s.Certificates > 0 {
		line := fmt.Sprintf("  certificates : %d", s.Certificates)
		var notes []string
		if s.Expired > 0 {
			notes = append(notes, fmt.Sprintf("%d expired", s.Expired))
		}
		if s.ExpiringSoon > 0 {
			notes = append(notes, fmt.Sprintf("%d expiring ≤%dd", s.ExpiringSoon, opts.ExpiringDays))
		}
		if len(notes) > 0 {
			line += " (" + strings.Join(notes, ", ") + ")"
		}
		b.WriteString(line + "\n")
	}
	if s.CSRs > 0 {
		fmt.Fprintf(&b, "  csr          : %d\n", s.CSRs)
	}
	if s.Containers > 0 {
		fmt.Fprintf(&b, "  containers   : %d\n", s.Containers)
	}
	return b.String()
}

func ofKind(fs []finding.Finding, kind finding.Kind) []finding.Finding {
	var out []finding.Finding
	for _, f := range fs {
		if f.Kind == kind {
			out = append(out, f)
		}
	}
	return out
}

// pathAt appends ":<line>" when material was found mid-file (line > 1),
// which is how embedded keys in config files are pointed at.
func pathAt(f finding.Finding) string {
	if f.Line > 1 {
		return fmt.Sprintf("%s:%d", f.Path, f.Line)
	}
	return f.Path
}

func algo(f finding.Finding) string {
	switch {
	case f.Algorithm == "":
		return "?"
	case f.Curve != "":
		return f.Algorithm + " " + f.Curve
	default:
		return f.Algorithm
	}
}

func bits(f finding.Finding) string {
	if f.Bits == 0 {
		return "-"
	}
	return fmt.Sprintf("%d", f.Bits)
}

func protection(f finding.Finding) string {
	if f.Protection == finding.ProtectionEncrypted && f.Cipher != "" {
		return "encrypted " + f.Cipher
	}
	return string(f.Protection)
}

// perms renders the octal mode and flags key files readable beyond the
// owner — the condition under which OpenSSH refuses an identity file.
func perms(f finding.Finding) string {
	p := fmt.Sprintf("%04o", f.Mode.Perm())
	if f.LoosePerms() {
		p += " !"
	}
	return p
}

func certStatus(f finding.Finding, now time.Time, expiringDays int) string {
	days := f.DaysLeft(now)
	switch {
	case f.Expired(now):
		return fmt.Sprintf("EXPIRED %dd ago", -days)
	case expiringDays > 0 && days < expiringDays:
		return fmt.Sprintf("expires in %dd !", days)
	default:
		return fmt.Sprintf("ok (%dd)", days)
	}
}

// table writes rows with two-space gutters and per-column alignment.
func table(b *strings.Builder, rows [][]string) {
	widths := make([]int, len(rows[0]))
	for _, row := range rows {
		for i, cell := range row {
			if w := len([]rune(cell)); w > widths[i] {
				widths[i] = w
			}
		}
	}
	for _, row := range rows {
		b.WriteString(" ")
		for i, cell := range row {
			b.WriteString(" ")
			b.WriteString(cell)
			if i < len(row)-1 {
				b.WriteString(strings.Repeat(" ", widths[i]-len([]rune(cell))))
			}
		}
		b.WriteString("\n")
	}
}
