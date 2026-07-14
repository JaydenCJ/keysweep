// Tests for the filesystem sweep: pruning, excludes, size caps, symlink
// policy, and deterministic ordering. Every test builds its own tree in
// t.TempDir(), so nothing leaks and nothing depends on the host.
package sweep

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/JaydenCJ/keysweep/internal/finding"
	"github.com/JaydenCJ/keysweep/internal/testkeys"
)

// place copies a fixture into the tree with the given mode.
func place(t *testing.T, root, rel, fixture string, mode os.FileMode) {
	t.Helper()
	abs := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, testkeys.Read(fixture), mode); err != nil {
		t.Fatal(err)
	}
}

func scan(t *testing.T, opts Options) Result {
	t.Helper()
	res, err := Scan(opts)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func paths(res Result) []string {
	out := make([]string, len(res.Findings))
	for i, f := range res.Findings {
		out[i] = f.Path
	}
	return out
}

func TestScanFindsMaterialAcrossSubdirectories(t *testing.T) {
	root := t.TempDir()
	place(t, root, "ssh/id_ed25519", "openssh_ed25519.key", 0o600)
	place(t, root, "tls/server.crt", "cert_leaf.pem", 0o644)
	place(t, root, "notes.txt", "embedded.env", 0o644)
	res := scan(t, Options{Root: root})
	if len(res.Findings) != 3 {
		t.Fatalf("want 3 findings, got %d: %v", len(res.Findings), paths(res))
	}
	if res.FilesScanned != 3 {
		t.Fatalf("files scanned: %d", res.FilesScanned)
	}
}

func TestFindingsAreSortedByPath(t *testing.T) {
	root := t.TempDir()
	place(t, root, "z.pem", "ec_p256_sec1.pem", 0o600)
	place(t, root, "a.pem", "rsa2048_pkcs1.pem", 0o600)
	place(t, root, "m/k.pem", "ed25519_pkcs8.pem", 0o600)
	res := scan(t, Options{Root: root, Jobs: 4})
	got := paths(res)
	want := []string{"a.pem", "m/k.pem", "z.pem"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order: got %v, want %v", got, want)
		}
	}
}

func TestDefaultPrunesAndAllOverride(t *testing.T) {
	root := t.TempDir()
	place(t, root, ".git/objects/key.pem", "rsa2048_pkcs1.pem", 0o644)
	place(t, root, "node_modules/pkg/test.key", "ec_p256_sec1.pem", 0o644)
	place(t, root, "real.key", "ed25519_pkcs8.pem", 0o600)
	res := scan(t, Options{Root: root})
	if got := paths(res); len(got) != 1 || got[0] != "real.key" {
		t.Fatalf("pruned dirs leaked: %v", got)
	}
	// --all reaches the pruned directories.
	res = scan(t, Options{Root: root, All: true})
	if len(res.Findings) != 3 {
		t.Fatalf("--all should reach pruned dirs: %v", paths(res))
	}
}

func TestExcludeGlobSkipsFilesAndDirectories(t *testing.T) {
	root := t.TempDir()
	place(t, root, "keep.pem", "ec_p256_sec1.pem", 0o600)
	place(t, root, "old.pem.bak", "rsa2048_pkcs1.pem", 0o600)
	place(t, root, "vendor/dep/k.pem", "ed25519_pkcs8.pem", 0o600)
	res := scan(t, Options{Root: root, Exclude: []string{"*.bak", "vendor/**"}})
	if got := paths(res); len(got) != 1 || got[0] != "keep.pem" {
		t.Fatalf("excludes not applied: %v", got)
	}
}

func TestSizeCapSkipsOversizedFiles(t *testing.T) {
	root := t.TempDir()
	place(t, root, "small.pem", "ec_p256_sec1.pem", 0o600)
	big := append([]byte{}, testkeys.Read("rsa2048_pkcs1.pem")...)
	big = append(big, make([]byte, 4096)...)
	if err := os.WriteFile(filepath.Join(root, "big.pem"), big, 0o600); err != nil {
		t.Fatal(err)
	}
	res := scan(t, Options{Root: root, MaxFileSize: 1024})
	if got := paths(res); len(got) != 1 || got[0] != "small.pem" {
		t.Fatalf("size cap not applied: %v", got)
	}
	if res.FilesSkipped != 1 {
		t.Fatalf("skipped count: %d", res.FilesSkipped)
	}
}

func TestSymlinksAreNeverFollowed(t *testing.T) {
	outside := t.TempDir()
	place(t, outside, "escape.pem", "rsa2048_pkcs1.pem", 0o600)
	root := t.TempDir()
	if err := os.Symlink(filepath.Join(outside, "escape.pem"), filepath.Join(root, "link.pem")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	res := scan(t, Options{Root: root})
	if len(res.Findings) != 0 {
		t.Fatalf("symlink followed: %v", paths(res))
	}
}

func TestSingleFileRootAndMissingRoot(t *testing.T) {
	root := t.TempDir()
	place(t, root, "id_rsa", "rsa2048_pkcs1.pem", 0o600)
	res := scan(t, Options{Root: filepath.Join(root, "id_rsa")})
	if len(res.Findings) != 1 || res.Findings[0].Path != "id_rsa" {
		t.Fatalf("got %v", paths(res))
	}
	if _, err := Scan(Options{Root: filepath.Join(root, "nope")}); err == nil {
		t.Fatal("missing root must error")
	}
}

func TestFileModeIsRecordedOnFindings(t *testing.T) {
	root := t.TempDir()
	place(t, root, "loose.pem", "ec_p256_sec1.pem", 0o644)
	place(t, root, "tight.pem", "rsa2048_pkcs1.pem", 0o600)
	res := scan(t, Options{Root: root})
	byPath := map[string]finding.Finding{}
	for _, f := range res.Findings {
		byPath[f.Path] = f
	}
	if !byPath["loose.pem"].LoosePerms() {
		t.Fatal("0644 must flag loose permissions")
	}
	if byPath["tight.pem"].LoosePerms() {
		t.Fatal("0600 must not flag")
	}
}

func TestParallelAndSerialScansAgree(t *testing.T) {
	root := t.TempDir()
	for i, fx := range []string{
		"rsa2048_pkcs1.pem", "ec_p256_sec1.pem", "ed25519_pkcs8.pem",
		"cert_leaf.pem", "fullchain.pem", "bundle.p12", "keystore.jks",
		"openssh_ed25519.key", "ppk3_ed25519.ppk", "embedded.env",
	} {
		place(t, root, filepath.Join("d", string(rune('a'+i)), fx), fx, 0o600)
	}
	serial := scan(t, Options{Root: root, Jobs: 1})
	parallel := scan(t, Options{Root: root, Jobs: 8})
	if len(serial.Findings) != len(parallel.Findings) {
		t.Fatalf("serial %d vs parallel %d", len(serial.Findings), len(parallel.Findings))
	}
	for i := range serial.Findings {
		if serial.Findings[i] != parallel.Findings[i] {
			t.Fatalf("finding %d differs:\n%+v\n%+v", i, serial.Findings[i], parallel.Findings[i])
		}
	}
}
