package crawler

import (
	"strings"
	"testing"
)

func TestSeedSegmentIsIdentifier(t *testing.T) {
	tests := []struct {
		seg  string
		want bool
	}{
		{"42", true},
		{"0", true},
		{"9f8ae1c2", true},                // hex run
		{"deadbeefcafe", true},            // long hex
		{"2026-08-06-a-post-title", true}, // dated slug
		{"2024-01-02", true},              // date (via pathshape)
		{"550e8400-e29b-41d4-a716-446655440000", true},
		{"about-us", false}, // slug without digits stays a section
		{"admin", false},
		{"products", false},
		{"v2", false},  // short, has a letter — a version segment, not an id
		{"abc", false}, // hex-ish but too short to be an id
		{"", false},
	}
	for _, tt := range tests {
		if got := seedSegmentIsIdentifier(tt.seg); got != tt.want {
			t.Errorf("seedSegmentIsIdentifier(%q) = %v, want %v", tt.seg, got, tt.want)
		}
	}
}

func TestSeedPathShape(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/product/1", "/product/*"},
		{"/product/2", "/product/*"},
		{"/product", "/product"},
		{"/admin/users/9f8ae1c2", "/admin/users/*"},
		{"/", "/"},
	}
	for _, tt := range tests {
		if got := seedPathShape(tt.path); got != tt.want {
			t.Errorf("seedPathShape(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
	// The whole point: per-record paths collapse together, named sections do not.
	if seedPathShape("/product/1") != seedPathShape("/product/2") {
		t.Error("two records of one template should share a shape")
	}
	if seedPathShape("/product") == seedPathShape("/admin") {
		t.Error("distinct named sections must not share a shape")
	}
}

func TestSeedIsDocument(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/about", true},  // extensionless route
		{"/about/", true}, // directory
		{"/index.html", true},
		{"/app.php", true},
		{"/logo.png", false},
		{"/bundle.js", false},
		{"/style.css", false},
		{"/feed.xml", false},
		{"/docs/v1.2/guide", true}, // dot is in a directory, not the filename
	}
	for _, tt := range tests {
		if got := seedIsDocument(tt.path); got != tt.want {
			t.Errorf("seedIsDocument(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestSelectCrawlableSeedsRoundsOverShapes(t *testing.T) {
	// A sitemap dominated by one template: without shape-aware selection the whole
	// budget is spent inside /blog and the structurally distinct sections at the
	// end of the file are never browsed.
	urls := []string{
		"https://app.test/blog/1", "https://app.test/blog/2", "https://app.test/blog/3",
		"https://app.test/blog/4", "https://app.test/blog/5", "https://app.test/blog/6",
		"https://app.test/admin",
		"https://app.test/settings",
	}

	got := selectCrawlableSeeds(urls, 4)
	if len(got) != 4 {
		t.Fatalf("selected %d seeds, want 4: %v", len(got), got)
	}

	var sawAdmin, sawSettings bool
	blogCount := 0
	for _, u := range got {
		switch {
		case strings.HasSuffix(u, "/admin"):
			sawAdmin = true
		case strings.HasSuffix(u, "/settings"):
			sawSettings = true
		case strings.Contains(u, "/blog/"):
			blogCount++
		}
	}
	if !sawAdmin || !sawSettings {
		t.Errorf("distinct sections were crowded out by the repeated template: %v", got)
	}
	if blogCount > 2 {
		t.Errorf("budget over-spent on one template: %d blog seeds in %v", blogCount, got)
	}
}

func TestSelectCrawlableSeedsDropsNonDocuments(t *testing.T) {
	urls := []string{
		"https://app.test/logo.png",
		"https://app.test/app.js",
		"https://app.test/about",
	}
	got := selectCrawlableSeeds(urls, 10)
	if len(got) != 1 || got[0] != "https://app.test/about" {
		t.Errorf("selectCrawlableSeeds kept non-documents: %v", got)
	}
}

func TestSelectCrawlableSeedsBounds(t *testing.T) {
	urls := []string{"https://app.test/a", "https://app.test/b"}
	if got := selectCrawlableSeeds(urls, 0); got != nil {
		t.Errorf("limit 0 should select nothing, got %v", got)
	}
	if got := selectCrawlableSeeds(nil, 5); got != nil {
		t.Errorf("no input should select nothing, got %v", got)
	}
	if got := selectCrawlableSeeds(urls, 100); len(got) != 2 {
		t.Errorf("a limit above the input size should return everything, got %v", got)
	}
}

// The in-page scripts carry %-signs of their own (URL-encoding character
// classes, a format-specifier guard), so they must not be rendered through a
// format-verb scan. Substitution is by token; assert no verb survives.
func TestInPageScriptsUseTokenSubstitution(t *testing.T) {
	for name, script := range map[string]string{
		"seedDiscoverScript":        seedDiscoverScript,
		"speculativeDiscoverScript": speculativeDiscoverScript,
		"registerFormProbeScript":   registerFormProbeScript,
	} {
		for _, verb := range []string{"%d", "%t", "%v", "%q"} {
			if strings.Contains(script, verb) {
				t.Errorf("%s still contains format verb %q; it must use a __TOKEN__ instead", name, verb)
			}
		}
	}
}

func TestSameDocumentURL(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"https://app.test/x", "https://app.test/x", true},
		{"https://app.test/x#", "https://app.test/x", true},
		{"https://app.test/x", "https://app.test/y", false},
		// A hash router expresses the route in the fragment, so it is significant.
		{"https://app.test/#/admin", "https://app.test/#/users", false},
		{"https://app.test/#/admin", "https://app.test/", false},
	}
	for _, tt := range tests {
		if got := sameDocumentURL(tt.a, tt.b); got != tt.want {
			t.Errorf("sameDocumentURL(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}
