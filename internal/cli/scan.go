package cli

import (
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/JaydenCJ/keysweep/internal/report"
	"github.com/JaydenCJ/keysweep/internal/sweep"
)

// scanFlags holds the flags shared by scan and check.
type scanFlags struct {
	format      string
	exclude     multiFlag
	maxFileSize int64
	all         bool
	jobs        int
	expiring    int
}

func (sf *scanFlags) register(fs *flag.FlagSet, defaultExpiring int) {
	fs.StringVar(&sf.format, "format", "text", "output format")
	fs.Var(&sf.exclude, "exclude", "glob to skip (repeatable)")
	fs.Int64Var(&sf.maxFileSize, "max-file-size", sweep.DefaultMaxFileSize, "size cap in bytes")
	fs.BoolVar(&sf.all, "all", false, "scan pruned directories too")
	fs.IntVar(&sf.jobs, "jobs", 0, "parallel workers")
	fs.IntVar(&sf.expiring, "expiring", defaultExpiring, "expiry warning window in days")
}

func (sf *scanFlags) options(root string) sweep.Options {
	return sweep.Options{
		Root:        root,
		Exclude:     sf.exclude,
		MaxFileSize: sf.maxFileSize,
		All:         sf.all,
		Jobs:        sf.jobs,
	}
}

func runScan(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("scan")
	var sf scanFlags
	sf.register(fs, 30)
	if code, ok := parseFlags(fs, args, stdout, stderr); !ok {
		return code
	}
	root, ok := pathArg(fs, stderr)
	if !ok {
		return ExitUsage
	}
	if sf.format != "text" && sf.format != "json" && sf.format != "markdown" {
		fmt.Fprintf(stderr, "keysweep: unknown --format %q (want text, json, or markdown)\n", sf.format)
		return ExitUsage
	}

	res, err := sweep.Scan(sf.options(root))
	if err != nil {
		fmt.Fprintf(stderr, "keysweep: %v\n", err)
		return ExitRuntime
	}

	now := time.Now()
	opts := report.Options{ExpiringDays: sf.expiring}
	switch sf.format {
	case "json":
		out, err := report.JSON(res, now, opts)
		if err != nil {
			fmt.Fprintf(stderr, "keysweep: %v\n", err)
			return ExitRuntime
		}
		fmt.Fprint(stdout, out)
	case "markdown":
		fmt.Fprint(stdout, report.Markdown(res, now, opts))
	default:
		fmt.Fprint(stdout, report.Text(res, now, opts))
	}
	return ExitOK
}
