// Tests for the exclude-glob matcher.
package sweep

import "testing"

func TestBareNameMatchesAnySegment(t *testing.T) {
	cases := []struct {
		pattern, rel string
		want         bool
	}{
		{"*.pem", "server.pem", true},
		{"*.pem", "deep/nested/server.pem", true},
		{"*.pem", "server.pem.bak", false},
		{"backup", "home/backup/id_rsa", true}, // matches a directory segment
		{"id_?sa", "ssh/id_rsa", true},
		{"*.p12", "ssh/id_rsa", false},
	}
	for _, c := range cases {
		if got := Match(c.pattern, c.rel); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.pattern, c.rel, got, c.want)
		}
	}
}

func TestPathPatternIsAnchored(t *testing.T) {
	if Match("ssh/id_rsa", "other/ssh/id_rsa") {
		t.Fatal("patterns with / anchor at the root")
	}
	if !Match("ssh/id_rsa", "ssh/id_rsa") {
		t.Fatal("exact path must match")
	}
}

func TestDoubleStarSpansSegments(t *testing.T) {
	cases := []struct {
		pattern, rel string
		want         bool
	}{
		{"vendor/**", "vendor/a/b/c.key", true},
		{"vendor/**", "vendor", true}, // ** matches zero segments
		{"vendor/**", "avendor/x", false},
		{"**/testdata/*", "a/b/testdata/k.pem", true},
		{"**/testdata/*", "testdata/k.pem", true},
		{"**/testdata/*", "testdata/sub/k.pem", false}, // trailing * is one segment
		{"a/**/z.pem", "a/z.pem", true},
		{"a/**/z.pem", "a/b/c/z.pem", true},
		{"a/**/z.pem", "b/a/z.pem", false},
	}
	for _, c := range cases {
		if got := Match(c.pattern, c.rel); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.pattern, c.rel, got, c.want)
		}
	}
}

func TestExcludedAnyOfAndInvalidPatterns(t *testing.T) {
	patterns := []string{"*.bak", "vendor/**"}
	if !Excluded(patterns, "keys/old.bak") {
		t.Fatal("first pattern should hit")
	}
	if !Excluded(patterns, "vendor/x/y.pem") {
		t.Fatal("second pattern should hit")
	}
	if Excluded(patterns, "keys/id_rsa") {
		t.Fatal("no pattern should hit")
	}
	if Excluded(nil, "anything") {
		t.Fatal("empty pattern list excludes nothing")
	}
	// Malformed patterns must fail closed (no match), never panic.
	if Match("[", "x") || Match("a/[/c", "a/b/c") {
		t.Fatal("malformed patterns must not match")
	}
}
