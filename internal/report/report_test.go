// Tests for the three renderers and the summary aggregation, against a
// fixed result set and a pinned clock — output must be byte-stable.
package report

import (
	"encoding/json"
	iofs "io/fs"
	"strings"
	"testing"
	"time"

	"github.com/JaydenCJ/keysweep/internal/finding"
	"github.com/JaydenCJ/keysweep/internal/parse"
	"github.com/JaydenCJ/keysweep/internal/sweep"
	"github.com/JaydenCJ/keysweep/internal/testkeys"
)

// The pinned clock all expiry math in these tests is computed against.
// Fixture cert validity windows are documented in package testkeys.
var now = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

var opts = Options{ExpiringDays: 30}

// fixtureResult builds a deterministic Result from committed fixtures.
func fixtureResult(t *testing.T) sweep.Result {
	t.Helper()
	var all []finding.Finding
	add := func(path, fixture string, mode uint32) {
		found := parse.File(testkeys.Read(fixture))
		if len(found) == 0 {
			t.Fatalf("fixture %s yielded nothing", fixture)
		}
		for i := range found {
			found[i].Path = path
			found[i].Mode = iofs.FileMode(mode)
		}
		all = append(all, found...)
	}
	add("ssh/id_ed25519", "openssh_ed25519.key", 0o600)
	add("ssh/id_rsa", "openssh_rsa3072_enc.key", 0o600)
	add("legacy/server.key", "rsa2048_pkcs1.pem", 0o644)
	add("tls/server.crt", "cert_leaf.pem", 0o644)
	add("tls/old.crt", "cert_expired.pem", 0o644)
	add("tls/soon.crt", "cert_expiring_soon.pem", 0o644)
	add("req.csr", "csr.pem", 0o644)
	add("bundle.p12", "bundle.p12", 0o600)
	finding.Sort(all)
	return sweep.Result{Root: "demo", Findings: all, FilesScanned: 8}
}

func TestSummarizeCounts(t *testing.T) {
	res := fixtureResult(t)
	s := Summarize(res.Findings, now, 30)
	if s.PrivateKeys != 3 || s.PlaintextKeys != 2 || s.EncryptedKeys != 1 {
		t.Fatalf("keys: %+v", s)
	}
	if s.LooseKeyPerms != 1 {
		t.Fatalf("loose perms: %+v", s)
	}
	if s.Certificates != 3 || s.Expired != 1 || s.ExpiringSoon != 1 {
		t.Fatalf("certs: %+v", s)
	}
	if s.CSRs != 1 || s.Containers != 1 {
		t.Fatalf("csr/containers: %+v", s)
	}
}

func TestSummarizeZeroWindowDisablesExpiringSoon(t *testing.T) {
	res := fixtureResult(t)
	s := Summarize(res.Findings, now, 0)
	if s.ExpiringSoon != 0 {
		t.Fatalf("window 0 must disable the bucket: %+v", s)
	}
	if s.Expired != 1 {
		t.Fatalf("expired is independent of the window: %+v", s)
	}
}

func TestTextReportSections(t *testing.T) {
	out := Text(fixtureResult(t), now, opts)
	for _, want := range []string{
		"keysweep scan — demo",
		"files scanned: 8 · findings: 8",
		"PRIVATE KEYS (3)",
		"CERTIFICATES (3)",
		"CERTIFICATE REQUESTS (1)",
		"CONTAINERS (1)",
		"SUMMARY",
		"private keys : 3 (2 plaintext, 1 encrypted; 1 with loose permissions)",
		"certificates : 3 (1 expired, 1 expiring ≤30d)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestTextReportKeyRows(t *testing.T) {
	out := Text(fixtureResult(t), now, opts)
	for _, want := range []string{
		"ed25519", "256", "openssh", "plaintext",
		"encrypted aes256-ctr", "3072",
		"0644 !", // the loose pkcs1 key
		"0600",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestTextReportCertStatuses(t *testing.T) {
	out := Text(fixtureResult(t), now, opts)
	// cert_expired: NotAfter 2025-01-01, 546 days before the pinned clock.
	if !strings.Contains(out, "EXPIRED 546d ago") {
		t.Errorf("expired status missing:\n%s", out)
	}
	// cert_expiring_soon: NotAfter 2026-07-15, 14 days out, inside 30d.
	if !strings.Contains(out, "expires in 14d !") {
		t.Errorf("expiring status missing:\n%s", out)
	}
	// cert_leaf: NotAfter 2036-01-01 → 3471 days from the pinned clock.
	if !strings.Contains(out, "ok (3471d)") {
		t.Errorf("ok status missing:\n%s", out)
	}
}

func TestEmptyScanRenderings(t *testing.T) {
	out := Text(sweep.Result{Root: "empty", FilesScanned: 4}, now, opts)
	if !strings.Contains(out, "no cryptographic material found") {
		t.Errorf("text: %s", out)
	}
	out = Markdown(sweep.Result{Root: "empty"}, now, opts)
	if !strings.Contains(out, "No cryptographic material found.") {
		t.Errorf("markdown: %s", out)
	}
}

func TestTextReportIsByteStable(t *testing.T) {
	a := Text(fixtureResult(t), now, opts)
	b := Text(fixtureResult(t), now, opts)
	if a != b {
		t.Fatal("identical input produced different output")
	}
}

func TestJSONEnvelopeAndSchema(t *testing.T) {
	out, err := JSON(fixtureResult(t), now, opts)
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if env["tool"] != "keysweep" || env["schema_version"] != float64(1) {
		t.Fatalf("envelope: %v %v", env["tool"], env["schema_version"])
	}
	if env["files_scanned"] != float64(8) {
		t.Fatalf("files_scanned: %v", env["files_scanned"])
	}
	findings := env["findings"].([]any)
	if len(findings) != 8 {
		t.Fatalf("findings: %d", len(findings))
	}
	summary := env["summary"].(map[string]any)
	if summary["plaintext_keys"] != float64(2) || summary["expired_certificates"] != float64(1) {
		t.Fatalf("summary: %+v", summary)
	}
}

func TestJSONCertificateFields(t *testing.T) {
	out, _ := JSON(fixtureResult(t), now, opts)
	var env struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatal(err)
	}
	var expired map[string]any
	for _, f := range env.Findings {
		if f["path"] == "tls/old.crt" {
			expired = f
		}
	}
	if expired == nil {
		t.Fatal("tls/old.crt missing")
	}
	if expired["expired"] != true {
		t.Fatalf("expired: %v", expired["expired"])
	}
	if expired["days_left"] != float64(-546) {
		t.Fatalf("days_left: %v", expired["days_left"])
	}
	if expired["self_signed"] != true {
		t.Fatalf("self_signed: %v", expired["self_signed"])
	}
	if expired["not_after"] != "2025-01-01T00:00:00Z" {
		t.Fatalf("not_after: %v", expired["not_after"])
	}
}

func TestJSONKeyFields(t *testing.T) {
	out, _ := JSON(fixtureResult(t), now, opts)
	var env struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatal(err)
	}
	for _, f := range env.Findings {
		if f["path"] == "legacy/server.key" {
			if f["loose_permissions"] != true || f["mode"] != "0644" {
				t.Fatalf("perms: %v %v", f["loose_permissions"], f["mode"])
			}
			if f["protection"] != "plaintext" || f["bits"] != float64(2048) {
				t.Fatalf("key fields: %+v", f)
			}
			// Certificate-only fields must be absent on keys.
			if _, ok := f["not_after"]; ok {
				t.Fatal("not_after leaked onto a key finding")
			}
			return
		}
	}
	t.Fatal("legacy/server.key missing")
}

func TestMarkdownTables(t *testing.T) {
	out := Markdown(fixtureResult(t), now, opts)
	for _, want := range []string{
		"## keysweep scan — `demo`",
		"### Private keys (3)",
		"| Path | Algorithm | Bits | Format | Protection | Perms |",
		"### Certificates (3)",
		"| `tls/old.crt` |",
		"### Summary",
		"**3** (2 plaintext, 1 encrypted, 1 with loose permissions)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestEmbeddedFindingRendersPathWithLine(t *testing.T) {
	found := parse.File(testkeys.Read("embedded.env"))
	found[0].Path = "deploy/.env"
	found[0].Mode = iofs.FileMode(0o600)
	res := sweep.Result{Root: "demo", Findings: found, FilesScanned: 1}
	out := Text(res, now, opts)
	if !strings.Contains(out, "deploy/.env:5") {
		t.Errorf("embedded key must show its line:\n%s", out)
	}
}
