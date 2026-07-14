package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/JaydenCJ/keysweep/internal/finding"
	"github.com/JaydenCJ/keysweep/internal/sweep"
)

// Markdown renders the report as GitHub-flavored Markdown, ready to paste
// into an issue, a PR description, or an audit document.
func Markdown(res sweep.Result, now time.Time, opts Options) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## keysweep scan — `%s`\n\n", res.Root)
	fmt.Fprintf(&b, "%s scanned, %s.\n",
		countNoun(res.FilesScanned, "file", "files"),
		countNoun(len(res.Findings), "finding", "findings"))

	if len(res.Findings) == 0 {
		b.WriteString("\nNo cryptographic material found.\n")
		return b.String()
	}

	keys := ofKind(res.Findings, finding.KindPrivateKey)
	certs := ofKind(res.Findings, finding.KindCertificate)
	csrs := ofKind(res.Findings, finding.KindCSR)
	containers := ofKind(res.Findings, finding.KindContainer)

	if len(keys) > 0 {
		fmt.Fprintf(&b, "\n### Private keys (%d)\n\n", len(keys))
		b.WriteString("| Path | Algorithm | Bits | Format | Protection | Perms |\n")
		b.WriteString("|---|---|---|---|---|---|\n")
		for _, f := range keys {
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s | `%s` |\n",
				pathAt(f), algo(f), bits(f), f.Format, protection(f), perms(f))
		}
	}
	if len(certs) > 0 {
		fmt.Fprintf(&b, "\n### Certificates (%d)\n\n", len(certs))
		b.WriteString("| Path | Subject | Algorithm | Bits | Not after | Status |\n")
		b.WriteString("|---|---|---|---|---|---|\n")
		for _, f := range certs {
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s | %s |\n",
				pathAt(f), f.Subject, algo(f), bits(f),
				f.NotAfter.Format("2006-01-02"), certStatus(f, now, opts.ExpiringDays))
		}
	}
	if len(csrs) > 0 {
		fmt.Fprintf(&b, "\n### Certificate requests (%d)\n\n", len(csrs))
		b.WriteString("| Path | Subject | Algorithm | Bits |\n")
		b.WriteString("|---|---|---|---|\n")
		for _, f := range csrs {
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", pathAt(f), f.Subject, algo(f), bits(f))
		}
	}
	if len(containers) > 0 {
		fmt.Fprintf(&b, "\n### Containers (%d)\n\n", len(containers))
		b.WriteString("| Path | Format | Protection |\n")
		b.WriteString("|---|---|---|\n")
		for _, f := range containers {
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n", pathAt(f), f.Format, f.Protection)
		}
	}

	s := Summarize(res.Findings, now, opts.ExpiringDays)
	b.WriteString("\n### Summary\n\n")
	fmt.Fprintf(&b, "- Private keys: **%d** (%d plaintext, %d encrypted, %d with loose permissions)\n",
		s.PrivateKeys, s.PlaintextKeys, s.EncryptedKeys, s.LooseKeyPerms)
	fmt.Fprintf(&b, "- Certificates: **%d** (%d expired, %d expiring soon)\n",
		s.Certificates, s.Expired, s.ExpiringSoon)
	fmt.Fprintf(&b, "- Certificate requests: **%d** · Containers: **%d**\n", s.CSRs, s.Containers)
	return b.String()
}

// countNoun renders a count with the right noun form, so the intro line
// never reads "1 findings".
func countNoun(n int, singular, plural string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", singular)
	}
	return fmt.Sprintf("%d %s", n, plural)
}
