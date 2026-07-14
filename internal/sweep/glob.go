package sweep

import (
	"path"
	"strings"
)

// Match reports whether a slash-separated relative path matches an exclude
// pattern.
//
// Semantics:
//   - A pattern without "/" matches against the file's base name and
//     against any single path segment ("*.pem" excludes every .pem file).
//   - A pattern with "/" matches against the whole relative path, where
//     "**" spans any number of segments ("vendor/**", "**/testdata/*").
//   - Within a segment, "*" and "?" behave like path.Match.
func Match(pattern, rel string) bool {
	if !strings.Contains(pattern, "/") {
		for _, seg := range strings.Split(rel, "/") {
			if ok, err := path.Match(pattern, seg); err == nil && ok {
				return true
			}
		}
		return false
	}
	return matchSegments(strings.Split(pattern, "/"), strings.Split(rel, "/"))
}

func matchSegments(pat, segs []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			// "**" absorbs zero or more leading segments.
			for i := 0; i <= len(segs); i++ {
				if matchSegments(pat[1:], segs[i:]) {
					return true
				}
			}
			return false
		}
		if len(segs) == 0 {
			return false
		}
		ok, err := path.Match(pat[0], segs[0])
		if err != nil || !ok {
			return false
		}
		pat = pat[1:]
		segs = segs[1:]
	}
	return len(segs) == 0
}

// Excluded reports whether rel matches any pattern in the list.
func Excluded(patterns []string, rel string) bool {
	for _, p := range patterns {
		if Match(p, rel) {
			return true
		}
	}
	return false
}
