// Package sweep discovers files worth inspecting and feeds them through
// the parsers. It owns everything filesystem-shaped: directory pruning,
// symlink policy, size caps, exclude globs, and the parallel worker pool.
package sweep

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/JaydenCJ/keysweep/internal/finding"
	"github.com/JaydenCJ/keysweep/internal/parse"
)

// DefaultMaxFileSize caps how many bytes of a single file are considered.
// Real key and certificate files are a few KiB; 1 MiB leaves generous room
// for CA bundles while keeping accidental scans of huge files cheap.
const DefaultMaxFileSize = 1 << 20

// defaultPrunes are directory names skipped unless Options.All is set.
// They are high-volume trees that hold third-party or derived content.
var defaultPrunes = map[string]bool{
	".git":         true,
	".hg":          true,
	".svn":         true,
	"node_modules": true,
	"__pycache__":  true,
	".cache":       true,
	".Trash":       true,
}

// Options configures one sweep.
type Options struct {
	Root        string   // directory or single file to scan
	Exclude     []string // glob patterns, see Match
	MaxFileSize int64    // bytes; 0 means DefaultMaxFileSize
	All         bool     // do not prune the default directory list
	Jobs        int      // parallel parser workers; 0 means NumCPU
}

// Result is the outcome of a sweep.
type Result struct {
	Root         string
	Findings     []finding.Finding
	FilesScanned int // regular files whose contents were inspected
	FilesSkipped int // files skipped: over the size cap or unreadable
}

type candidate struct {
	rel  string
	abs  string
	mode fs.FileMode
}

// Scan walks the root and returns every finding, sorted deterministically.
// Symlinks are never followed: the inventory reports where material
// physically lives, and following links would double-count or escape the
// root.
func Scan(opts Options) (Result, error) {
	maxSize := opts.MaxFileSize
	if maxSize <= 0 {
		maxSize = DefaultMaxFileSize
	}
	jobs := opts.Jobs
	if jobs <= 0 {
		jobs = runtime.NumCPU()
	}

	res := Result{Root: opts.Root}
	info, err := os.Lstat(opts.Root)
	if err != nil {
		return res, fmt.Errorf("cannot scan %s: %w", opts.Root, err)
	}

	var candidates []candidate
	skipped := 0
	if !info.IsDir() {
		if info.Size() > maxSize {
			return res, fmt.Errorf("%s exceeds the %d-byte size cap", opts.Root, maxSize)
		}
		candidates = append(candidates, candidate{
			rel: filepath.Base(opts.Root), abs: opts.Root, mode: info.Mode(),
		})
	} else {
		walkErr := filepath.WalkDir(opts.Root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				skipped++
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			rel, rerr := filepath.Rel(opts.Root, path)
			if rerr != nil {
				return rerr
			}
			rel = filepath.ToSlash(rel)
			if d.IsDir() {
				if path != opts.Root && !opts.All && defaultPrunes[d.Name()] {
					return fs.SkipDir
				}
				if rel != "." && Excluded(opts.Exclude, rel) {
					return fs.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() { // symlinks, sockets, devices
				return nil
			}
			if Excluded(opts.Exclude, rel) {
				return nil
			}
			fi, ierr := d.Info()
			if ierr != nil {
				skipped++
				return nil
			}
			if fi.Size() > maxSize {
				skipped++
				return nil
			}
			candidates = append(candidates, candidate{rel: rel, abs: path, mode: fi.Mode()})
			return nil
		})
		if walkErr != nil {
			return res, walkErr
		}
	}

	findings, scanned, unreadable := parseAll(candidates, jobs)
	res.Findings = findings
	res.FilesScanned = scanned
	res.FilesSkipped = skipped + unreadable
	finding.Sort(res.Findings)
	return res, nil
}

// parseAll reads and parses candidates with a bounded worker pool.
func parseAll(candidates []candidate, jobs int) (fs []finding.Finding, scanned, unreadable int) {
	if jobs > len(candidates) && len(candidates) > 0 {
		jobs = len(candidates)
	}
	type slot struct {
		findings []finding.Finding
		read     bool
	}
	slots := make([]slot, len(candidates))
	work := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < jobs; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range work {
				c := candidates[i]
				content, err := os.ReadFile(c.abs)
				if err != nil {
					continue
				}
				found := parse.File(content)
				for j := range found {
					found[j].Path = c.rel
					found[j].Mode = c.mode
				}
				slots[i] = slot{findings: found, read: true}
			}
		}()
	}
	for i := range candidates {
		work <- i
	}
	close(work)
	wg.Wait()

	for _, s := range slots {
		if !s.read {
			unreadable++
			continue
		}
		scanned++
		fs = append(fs, s.findings...)
	}
	return fs, scanned, unreadable
}
