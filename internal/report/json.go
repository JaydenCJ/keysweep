package report

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/JaydenCJ/keysweep/internal/finding"
	"github.com/JaydenCJ/keysweep/internal/sweep"
	"github.com/JaydenCJ/keysweep/internal/version"
)

// jsonFinding is the wire shape of one finding. Field order and names are
// part of the schema_version 1 contract.
type jsonFinding struct {
	Path       string `json:"path"`
	Line       int    `json:"line,omitempty"`
	Kind       string `json:"kind"`
	Format     string `json:"format"`
	Algorithm  string `json:"algorithm,omitempty"`
	Curve      string `json:"curve,omitempty"`
	Bits       int    `json:"bits,omitempty"`
	Protection string `json:"protection"`
	Cipher     string `json:"cipher,omitempty"`

	Subject    string `json:"subject,omitempty"`
	Issuer     string `json:"issuer,omitempty"`
	NotBefore  string `json:"not_before,omitempty"`
	NotAfter   string `json:"not_after,omitempty"`
	DaysLeft   *int   `json:"days_left,omitempty"`
	Expired    *bool  `json:"expired,omitempty"`
	SelfSigned *bool  `json:"self_signed,omitempty"`
	IsCA       *bool  `json:"is_ca,omitempty"`

	Mode       string `json:"mode"`
	LoosePerms *bool  `json:"loose_permissions,omitempty"`
}

type jsonSummary struct {
	PrivateKeys   int `json:"private_keys"`
	PlaintextKeys int `json:"plaintext_keys"`
	EncryptedKeys int `json:"encrypted_keys"`
	LooseKeyPerms int `json:"loose_permission_keys"`
	Certificates  int `json:"certificates"`
	Expired       int `json:"expired_certificates"`
	ExpiringSoon  int `json:"expiring_certificates"`
	CSRs          int `json:"certificate_requests"`
	Containers    int `json:"containers"`
}

type jsonEnvelope struct {
	Tool          string        `json:"tool"`
	Version       string        `json:"version"`
	SchemaVersion int           `json:"schema_version"`
	Root          string        `json:"root"`
	GeneratedAt   string        `json:"generated_at"`
	FilesScanned  int           `json:"files_scanned"`
	FilesSkipped  int           `json:"files_skipped"`
	Findings      []jsonFinding `json:"findings"`
	Summary       jsonSummary   `json:"summary"`
}

// JSON renders the machine-readable report (schema_version 1).
func JSON(res sweep.Result, now time.Time, opts Options) (string, error) {
	env := jsonEnvelope{
		Tool:          "keysweep",
		Version:       version.Version,
		SchemaVersion: 1,
		Root:          res.Root,
		GeneratedAt:   now.UTC().Format(time.RFC3339),
		FilesScanned:  res.FilesScanned,
		FilesSkipped:  res.FilesSkipped,
		Findings:      make([]jsonFinding, 0, len(res.Findings)),
	}
	for _, f := range res.Findings {
		jf := jsonFinding{
			Path:       f.Path,
			Line:       f.Line,
			Kind:       string(f.Kind),
			Format:     f.Format,
			Algorithm:  f.Algorithm,
			Curve:      f.Curve,
			Bits:       f.Bits,
			Protection: string(f.Protection),
			Cipher:     f.Cipher,
			Mode:       fmt.Sprintf("%04o", f.Mode.Perm()),
		}
		if f.Kind == finding.KindCertificate {
			days := f.DaysLeft(now)
			expired := f.Expired(now)
			jf.Subject = f.Subject
			jf.Issuer = f.Issuer
			jf.NotBefore = f.NotBefore.Format(time.RFC3339)
			jf.NotAfter = f.NotAfter.Format(time.RFC3339)
			jf.DaysLeft = &days
			jf.Expired = &expired
			jf.SelfSigned = boolPtr(f.SelfSigned)
			jf.IsCA = boolPtr(f.IsCA)
		}
		if f.Kind == finding.KindCSR {
			jf.Subject = f.Subject
		}
		if f.Kind == finding.KindPrivateKey || f.Kind == finding.KindContainer {
			jf.LoosePerms = boolPtr(f.LoosePerms())
		}
		env.Findings = append(env.Findings, jf)
	}
	s := Summarize(res.Findings, now, opts.ExpiringDays)
	env.Summary = jsonSummary{
		PrivateKeys:   s.PrivateKeys,
		PlaintextKeys: s.PlaintextKeys,
		EncryptedKeys: s.EncryptedKeys,
		LooseKeyPerms: s.LooseKeyPerms,
		Certificates:  s.Certificates,
		Expired:       s.Expired,
		ExpiringSoon:  s.ExpiringSoon,
		CSRs:          s.CSRs,
		Containers:    s.Containers,
	}
	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out) + "\n", nil
}

func boolPtr(b bool) *bool { return &b }
