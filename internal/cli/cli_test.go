// In-process integration tests for the CLI: subcommand routing, flags,
// output formats, and exit codes, over trees built from committed
// fixtures in t.TempDir().
package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JaydenCJ/keysweep/internal/testkeys"
	"github.com/JaydenCJ/keysweep/internal/version"
)

// run executes the CLI in-process and captures both streams.
func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = Run(args, &out, &errb)
	return code, out.String(), errb.String()
}

// demoTree builds a small realistic tree and returns its root.
func demoTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	place := func(rel, fixture string, mode os.FileMode) {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, testkeys.Read(fixture), mode); err != nil {
			t.Fatal(err)
		}
	}
	place("ssh/id_ed25519", "openssh_ed25519.key", 0o600)
	place("ssh/id_rsa", "openssh_rsa3072_enc.key", 0o600)
	place("tls/server.crt", "cert_leaf.pem", 0o644)
	place("tls/old.crt", "cert_expired.pem", 0o644)
	place("legacy/backup.p12", "bundle.p12", 0o600)
	place("README.txt", "embedded.env", 0o644) // embedded key in a text file
	return root
}

func TestVersionSubcommandAndFlagAlias(t *testing.T) {
	code, out, _ := run(t, "version")
	if code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	if strings.TrimSpace(out) != "keysweep "+version.Version {
		t.Fatalf("got %q", out)
	}
	code, out2, _ := run(t, "--version")
	if code != ExitOK || out2 != out {
		t.Fatalf("--version must match: exit %d, out %q", code, out2)
	}
}

func TestHelpPrintsUsage(t *testing.T) {
	code, out, _ := run(t, "help")
	if code != ExitOK || !strings.Contains(out, "Usage:") || !strings.Contains(out, "Exit codes") {
		t.Fatalf("exit %d, out %q", code, out)
	}
}

func TestHelpFlagOnSubcommandExitsZero(t *testing.T) {
	// -h must be help (exit 0, usage on stdout), not a usage *error*.
	for _, args := range [][]string{{"scan", "-h"}, {"check", "--help"}} {
		code, out, _ := run(t, args...)
		if code != ExitOK || !strings.Contains(out, "Usage:") {
			t.Errorf("%v: exit %d, out %q", args, code, out)
		}
	}
}

func TestScanTextReport(t *testing.T) {
	root := demoTree(t)
	code, out, stderr := run(t, "scan", root)
	if code != ExitOK {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	for _, want := range []string{
		"PRIVATE KEYS (3)", "CERTIFICATES (2)", "CONTAINERS (1)",
		"ed25519", "encrypted aes256-ctr", "EXPIRED", "README.txt:5",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// A bare path (no "scan" word) must behave identically.
	code, out2, _ := run(t, root)
	if code != ExitOK || out2 != out {
		t.Fatalf("implicit scan differs: exit %d", code)
	}
}

func TestScanJSONIsParseable(t *testing.T) {
	code, out, _ := run(t, "scan", "--format", "json", demoTree(t))
	if code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	var env struct {
		Tool          string           `json:"tool"`
		SchemaVersion int              `json:"schema_version"`
		Findings      []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if env.Tool != "keysweep" || env.SchemaVersion != 1 || len(env.Findings) != 6 {
		t.Fatalf("envelope: %+v", env)
	}
}

func TestScanMarkdown(t *testing.T) {
	code, out, _ := run(t, "scan", "--format", "markdown", demoTree(t))
	if code != ExitOK || !strings.Contains(out, "### Private keys (3)") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

func TestScanExcludeFlagRepeats(t *testing.T) {
	code, out, _ := run(t, "scan", "--exclude", "tls/**", "--exclude", "*.p12",
		"--format", "json", demoTree(t))
	if code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	if strings.Contains(out, "tls/") || strings.Contains(out, ".p12") {
		t.Fatalf("excludes ignored:\n%s", out)
	}
}

func TestScanSingleFile(t *testing.T) {
	root := demoTree(t)
	code, out, _ := run(t, "scan", filepath.Join(root, "ssh", "id_rsa"))
	if code != ExitOK || !strings.Contains(out, "PRIVATE KEYS (1)") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

func TestUsageErrorsExitTwo(t *testing.T) {
	root := demoTree(t)
	cases := [][]string{
		{"scan", "--format", "yaml", root},      // unknown scan format
		{"scan", "--frobnicate"},                // unknown flag
		{"scan", "a", "b"},                      // too many positionals
		{"check", "--format", "markdown", root}, // markdown is scan-only
	}
	for _, args := range cases {
		if code, _, _ := run(t, args...); code != ExitUsage {
			t.Errorf("%v: exit %d, want %d", args, code, ExitUsage)
		}
	}
}

func TestScanMissingRootExitsRuntime(t *testing.T) {
	code, _, stderr := run(t, "scan", filepath.Join(t.TempDir(), "absent"))
	if code != ExitRuntime || !strings.Contains(stderr, "keysweep:") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestCheckFailsOnRiskyTree(t *testing.T) {
	code, out, _ := run(t, "check", demoTree(t))
	if code != ExitBreach {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, want := range []string{"plaintext-key", "expired", "check:", "FAIL"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestCheckSummaryUsesSingularNouns(t *testing.T) {
	// One plaintext key: the verdict line must not read "1 files … 1 breaches".
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "id_ed25519"),
		testkeys.Read("openssh_ed25519.key"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := run(t, "check", root)
	if code != ExitBreach {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if !strings.Contains(out, "check: 1 file scanned, 1 finding, 1 breach — FAIL") {
		t.Fatalf("singular verdict line missing:\n%s", out)
	}
}

func TestCheckPassesOnCleanTree(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "id_rsa"),
		testkeys.Read("openssh_rsa3072_enc.key"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := run(t, "check", root)
	if code != ExitOK || !strings.Contains(out, "PASS") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

func TestCheckAllowPlaintextNarrowsTheGate(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "id_ed25519"),
		testkeys.Read("openssh_ed25519.key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := run(t, "check", root); code != ExitBreach {
		t.Fatalf("plaintext key should breach by default: %s", out)
	}
	code, out, _ := run(t, "check", "--allow-plaintext", root)
	if code != ExitOK {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

func TestCheckExpiringWindow(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "server.crt"),
		testkeys.Read("cert_leaf.pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	// cert_leaf is valid until 2036 — passes with no window, fails with an
	// absurdly long one. (36500 days ≈ a century.)
	if code, out, _ := run(t, "check", root); code != ExitOK {
		t.Fatalf("valid cert must pass:\n%s", out)
	}
	code, out, _ := run(t, "check", "--expiring", "36500", root)
	if code != ExitBreach || !strings.Contains(out, "expiring") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

func TestCheckJSONFormat(t *testing.T) {
	code, out, _ := run(t, "check", "--format", "json", demoTree(t))
	if code != ExitBreach {
		t.Fatalf("exit %d", code)
	}
	var env struct {
		Pass     bool             `json:"pass"`
		Breaches []map[string]any `json:"breaches"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if env.Pass || len(env.Breaches) == 0 {
		t.Fatalf("got %+v", env)
	}
}

func TestCheckMinRSABits(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "weak.pem"),
		testkeys.Read("rsa2048_pkcs1.pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := run(t, "check", "--allow-plaintext", "--min-rsa-bits", "3072", root)
	if code != ExitBreach || !strings.Contains(out, "weak-rsa") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}
