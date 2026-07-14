// Package cli wires the keysweep subcommands. Run is in-process and takes
// explicit writers, so integration tests drive the full CLI without
// spawning a binary.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/JaydenCJ/keysweep/internal/version"
)

// Exit codes, stable across releases:
const (
	ExitOK      = 0 // scan succeeded / check passed
	ExitBreach  = 1 // check found at least one policy breach
	ExitUsage   = 2 // bad flags or arguments
	ExitRuntime = 3 // I/O or environment failure
)

const usageText = `keysweep — inventory every private key and certificate on disk

Usage:
  keysweep [scan] [flags] [path]     inventory a directory (default ".")
  keysweep check [flags] [path]      fail (exit 1) on risky material
  keysweep version                   print the version

Scan flags:
  --format FORMAT      text, json, or markdown (default text)
  --exclude GLOB       skip matching paths; repeatable ("*.bak", "vendor/**")
  --max-file-size N    skip files larger than N bytes (default 1048576)
  --all                also scan .git, node_modules, and other pruned dirs
  --jobs N             parallel workers (default: CPU count)
  --expiring N         flag certificates expiring within N days (default 30)

Check flags (in addition to scan flags):
  --allow-plaintext    do not fail on unencrypted private keys
  --ignore-perms       do not fail on group/world-readable key files
  --min-rsa-bits N     fail RSA keys smaller than N bits (default 0 = off)
  (--expiring defaults to 0 for check: only already-expired certs fail)

Exit codes: 0 ok · 1 policy breach · 2 usage error · 3 runtime error
`

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string { return fmt.Sprint([]string(*m)) }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// Run executes the CLI and returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return runScan(nil, stdout, stderr)
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "check":
		return runCheck(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "keysweep %s\n", version.Version)
		return ExitOK
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usageText)
		return ExitOK
	default:
		// Bare flags or a path mean the implicit scan subcommand.
		return runScan(args, stdout, stderr)
	}
}

// newFlagSet builds a silent FlagSet; parseFlags renders help and errors.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {} // rendered by parseFlags, not the flag package
	return fs
}

// parseFlags parses args and renders help/errors consistently: -h/--help
// prints usage to stdout and exits 0; a bad flag gets a one-line pointer to
// `keysweep help` and exits 2. The bool is false when the caller should
// return the code immediately.
func parseFlags(fs *flag.FlagSet, args []string, stdout, stderr io.Writer) (int, bool) {
	err := fs.Parse(args)
	switch {
	case err == nil:
		return ExitOK, true
	case errors.Is(err, flag.ErrHelp):
		fmt.Fprint(stdout, usageText)
		return ExitOK, false
	default:
		fmt.Fprintf(stderr, "keysweep: %v (run \"keysweep help\" for usage)\n", err)
		return ExitUsage, false
	}
}

// countNoun renders a count with the right noun form, so reports never say
// "1 breaches" or "1 findings".
func countNoun(n int, singular, plural string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", singular)
	}
	return fmt.Sprintf("%d %s", n, plural)
}

// pathArg extracts the optional single positional path argument.
func pathArg(fs *flag.FlagSet, stderr io.Writer) (string, bool) {
	switch fs.NArg() {
	case 0:
		return ".", true
	case 1:
		return fs.Arg(0), true
	default:
		fmt.Fprintf(stderr, "keysweep: expected at most one path, got %d\n", fs.NArg())
		return "", false
	}
}
