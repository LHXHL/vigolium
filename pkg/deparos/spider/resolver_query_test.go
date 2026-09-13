package spider

import (
	"net/url"
	"testing"
)

// TestResolvePreservesQuerySemantics pins B13: sanitization must not rewrite a
// query into a different request.
//
// Relative references were cleaned as ONE string before being parsed, so the
// path rules ran over the query too. Two of them change meaning rather than
// merely tidying: PathUnescape turns %26 into a literal '&' (splitting one
// parameter into two) and the "//" -> "/" collapse mangles an embedded absolute
// URL. Both yield a URL that parses cleanly and asks the application for
// something it never offered — worse than dropping the candidate outright,
// because nothing downstream can tell.
//
// The absolute-URL branch was always safe (url.Parse separated the components
// for it), so these cases are all relative references, which is what an href or
// a mined string almost always is.
func TestResolvePreservesQuerySemantics(t *testing.T) {
	resolver := NewURLResolver()
	base := mustParseURL("https://example.com/app/")

	cases := []struct {
		name     string
		relative string
		wantPath string
		// wantQuery is compared after parsing, so key/value identity is what is
		// asserted rather than byte-level spelling.
		wantQuery url.Values
	}{
		{
			name:      "encoded ampersand stays inside one value",
			relative:  "/item?label=a%26b",
			wantPath:  "/item",
			wantQuery: url.Values{"label": {"a&b"}},
		},
		{
			name:      "encoded equals stays inside one value",
			relative:  "/item?token=a%3Db",
			wantPath:  "/item",
			wantQuery: url.Values{"token": {"a=b"}},
		},
		{
			name:      "embedded absolute URL keeps its double slash",
			relative:  "/login?next=https%3A%2F%2Fexample.com%2Fdash",
			wantPath:  "/login",
			wantQuery: url.Values{"next": {"https://example.com/dash"}},
		},
		{
			name:      "unencoded embedded URL is not slash-collapsed",
			relative:  "/login?next=https://example.com/dash",
			wantPath:  "/login",
			wantQuery: url.Values{"next": {"https://example.com/dash"}},
		},
		{
			name:      "repeated keys survive",
			relative:  "/search?tag=a&tag=b",
			wantPath:  "/search",
			wantQuery: url.Values{"tag": {"a", "b"}},
		},
		{
			name:      "encoded plus is not turned into a space delimiter",
			relative:  "/calc?expr=1%2B1",
			wantPath:  "/calc",
			wantQuery: url.Values{"expr": {"1+1"}},
		},
		{
			name:      "relative path with query resolves against the base",
			relative:  "detail?id=7",
			wantPath:  "/app/detail",
			wantQuery: url.Values{"id": {"7"}},
		},
		{
			name:      "parent traversal still resolves with the query intact",
			relative:  "../api/v1?q=a%26b",
			wantPath:  "/api/v1",
			wantQuery: url.Values{"q": {"a&b"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolver.Resolve(base, tc.relative)
			if err != nil {
				t.Fatalf("Resolve(%q): %v", tc.relative, err)
			}
			if got.Path != tc.wantPath {
				t.Errorf("path = %q, want %q (full: %s)", got.Path, tc.wantPath, got)
			}

			gotQuery := got.Query()
			if len(gotQuery) != len(tc.wantQuery) {
				t.Fatalf("query has %d key(s) %v, want %d %v (full: %s)",
					len(gotQuery), gotQuery, len(tc.wantQuery), tc.wantQuery, got)
			}
			for k, want := range tc.wantQuery {
				have := gotQuery[k]
				if len(have) != len(want) {
					t.Errorf("query[%q] = %v, want %v (full: %s)", k, have, want, got)
					continue
				}
				for i := range want {
					if have[i] != want[i] {
						t.Errorf("query[%q][%d] = %q, want %q (full: %s)", k, i, have[i], want[i], got)
					}
				}
			}
		})
	}
}

// TestResolveStillRecoversNoisyMinedStrings is the counterweight. The
// sanitization exists because URLs mined out of JavaScript arrive wrapped in
// escapes and quotes, and narrowing it for the query's sake must not cost that
// recovery. These are the shapes the cleanup was written for.
func TestResolveStillRecoversNoisyMinedStrings(t *testing.T) {
	resolver := NewURLResolver()
	base := mustParseURL("https://example.com/")

	cases := []struct {
		name     string
		relative string
		wantPath string
	}{
		{"JS-escaped slashes", `\/trading\/positions`, "/trading/positions"},
		{"quote wrapped", `"/api/orders"`, "/api/orders"},
		{"single-quote wrapped", `'/api/orders'`, "/api/orders"},
		{"backtick wrapped", "`/api/orders`", "/api/orders"},
		{"embedded newline", "/api/\norders", "/api/orders"},
		{"double slash collapsed in path", "/api//v2//users", "/api/v2/users"},
		{"unbalanced bracket segment", "/v2/]/v2/welcome", "/v2/v2/welcome"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolver.Resolve(base, tc.relative)
			if err != nil {
				t.Fatalf("Resolve(%q): %v", tc.relative, err)
			}
			if got.Path != tc.wantPath {
				t.Errorf("path = %q, want %q (full: %s)", got.Path, tc.wantPath, got)
			}
		})
	}
}

// TestResolveCleansSourceNoiseInsideTheQueryToo checks that narrowing the query
// rules did not make them a no-op: JS escapes and stray quotes are noise
// wherever they appear, and only the semantics-changing rules (percent-decoding,
// slash collapsing) were withheld.
func TestResolveCleansSourceNoiseInsideTheQueryToo(t *testing.T) {
	resolver := NewURLResolver()
	base := mustParseURL("https://example.com/")

	got, err := resolver.Resolve(base, `"/search?q=widgets&sort=name"`)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Path != "/search" {
		t.Errorf("path = %q, want /search", got.Path)
	}
	q := got.Query()
	if q.Get("q") != "widgets" {
		t.Errorf("q = %q, want %q — a trailing quote from the JS string literal "+
			"leaked into the query value", q.Get("q"), "widgets")
	}
	if q.Get("sort") != "name" {
		t.Errorf("sort = %q, want %q", q.Get("sort"), "name")
	}
}

// TestSplitPathFromQuery covers the delimiter handling directly, including the
// references that are query- or fragment-only.
func TestSplitPathFromQuery(t *testing.T) {
	cases := []struct {
		in         string
		wantPath   string
		wantSuffix string
	}{
		{"/a/b", "/a/b", ""},
		{"/a/b?x=1", "/a/b", "?x=1"},
		{"/a/b#frag", "/a/b", "#frag"},
		{"/a/b?x=1#frag", "/a/b", "?x=1#frag"},
		{"?x=1", "", "?x=1"},
		{"#frag", "", "#frag"},
		{"", "", ""},
		// A '#' before a '?' means the '?' is part of the fragment.
		{"/a#f?notquery", "/a", "#f?notquery"},
	}

	for _, tc := range cases {
		path, suffix := splitPathFromQuery(tc.in)
		if path != tc.wantPath || suffix != tc.wantSuffix {
			t.Errorf("splitPathFromQuery(%q) = (%q, %q), want (%q, %q)",
				tc.in, path, suffix, tc.wantPath, tc.wantSuffix)
		}
	}
}
