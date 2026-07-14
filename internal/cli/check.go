package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/JaydenCJ/keysweep/internal/policy"
	"github.com/JaydenCJ/keysweep/internal/sweep"
)

// runCheck scans and then applies the policy gate: exit 1 when any risky
// material is found, so it slots into pre-push hooks and release scripts.
func runCheck(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("check")
	var sf scanFlags
	// For the gate, --expiring defaults to 0: only already-expired
	// certificates fail unless the caller opts into a look-ahead window.
	sf.register(fs, 0)
	rules := policy.Rules{}
	fs.BoolVar(&rules.AllowPlaintext, "allow-plaintext", false, "do not fail on plaintext keys")
	fs.BoolVar(&rules.IgnorePerms, "ignore-perms", false, "do not fail on loose permissions")
	fs.IntVar(&rules.MinRSABits, "min-rsa-bits", 0, "fail RSA keys below N bits")
	if code, ok := parseFlags(fs, args, stdout, stderr); !ok {
		return code
	}
	root, ok := pathArg(fs, stderr)
	if !ok {
		return ExitUsage
	}
	if sf.format != "text" && sf.format != "json" {
		fmt.Fprintf(stderr, "keysweep: unknown --format %q (check supports text or json)\n", sf.format)
		return ExitUsage
	}
	rules.ExpiringDays = sf.expiring

	res, err := sweep.Scan(sf.options(root))
	if err != nil {
		fmt.Fprintf(stderr, "keysweep: %v\n", err)
		return ExitRuntime
	}
	breaches := policy.Evaluate(res.Findings, time.Now(), rules)

	if sf.format == "json" {
		type jsonBreach struct {
			Rule    string `json:"rule"`
			Path    string `json:"path"`
			Line    int    `json:"line,omitempty"`
			Message string `json:"message"`
		}
		env := struct {
			Tool         string       `json:"tool"`
			Root         string       `json:"root"`
			FilesScanned int          `json:"files_scanned"`
			Findings     int          `json:"findings"`
			Breaches     []jsonBreach `json:"breaches"`
			Pass         bool         `json:"pass"`
		}{
			Tool: "keysweep", Root: res.Root,
			FilesScanned: res.FilesScanned, Findings: len(res.Findings),
			Breaches: make([]jsonBreach, 0, len(breaches)),
			Pass:     len(breaches) == 0,
		}
		for _, b := range breaches {
			env.Breaches = append(env.Breaches, jsonBreach(b))
		}
		out, jerr := json.MarshalIndent(env, "", "  ")
		if jerr != nil {
			fmt.Fprintf(stderr, "keysweep: %v\n", jerr)
			return ExitRuntime
		}
		fmt.Fprintln(stdout, string(out))
	} else {
		for _, b := range breaches {
			loc := b.Path
			if b.Line > 1 {
				loc = fmt.Sprintf("%s:%d", b.Path, b.Line)
			}
			fmt.Fprintf(stdout, "BREACH %-18s %s — %s\n", b.Rule, loc, b.Message)
		}
		fmt.Fprintf(stdout, "check: %s scanned, %s, %s — ",
			countNoun(res.FilesScanned, "file", "files"),
			countNoun(len(res.Findings), "finding", "findings"),
			countNoun(len(breaches), "breach", "breaches"))
		if len(breaches) == 0 {
			fmt.Fprintln(stdout, "PASS")
		} else {
			fmt.Fprintln(stdout, "FAIL")
		}
	}

	if len(breaches) > 0 {
		return ExitBreach
	}
	return ExitOK
}
