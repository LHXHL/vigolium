package crawler

import (
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestResolveExtraSeedHistoryRoutes(t *testing.T) {
	start := mustURL(t, "https://app.test/home?x=1#top")
	cases := []struct {
		seed config.ExtraSeed
		want string
		ok   bool
	}{
		{config.ExtraSeed{URL: "/users/:id"}, "https://app.test/users/1", true},
		{config.ExtraSeed{URL: "/org/[org]/settings", Mode: config.SeedModeHistory}, "https://app.test/org/1/settings", true},
		{config.ExtraSeed{URL: "https://app.test:8443/admin/reports/:reportId"}, "https://app.test:8443/admin/reports/1", true},
		{config.ExtraSeed{URL: "/files/*"}, "", false},
		{config.ExtraSeed{URL: "javascript:alert(1)"}, "", false},
		{config.ExtraSeed{URL: "  "}, "", false},
	}
	for _, tc := range cases {
		got, ok := ResolveExtraSeed(start, tc.seed, false)
		if got != tc.want || ok != tc.ok {
			t.Errorf("ResolveExtraSeed(%+v) = %q, %v; want %q, %v", tc.seed, got, ok, tc.want, tc.ok)
		}
	}
}

func TestResolveExtraSeedHashRoutes(t *testing.T) {
	start := mustURL(t, "https://app.test/app/index.html#/login")
	cases := []struct {
		name    string
		seed    config.ExtraSeed
		hashApp bool
		want    string
	}{
		{"explicit fragment route", config.ExtraSeed{URL: "#/users/:id"}, false, "https://app.test/app/index.html#/users/1"},
		{"hashbang kept", config.ExtraSeed{URL: "#!/reports/:id"}, false, "https://app.test/app/index.html#!/reports/1"},
		{"hash mode on a path", config.ExtraSeed{URL: "/settings/profile", Mode: config.SeedModeHash}, false, "https://app.test/app/index.html#/settings/profile"},
		{"auto follows a hash-routed app", config.ExtraSeed{URL: "/settings"}, true, "https://app.test/app/index.html#/settings"},
		{"history mode wins over a hash app", config.ExtraSeed{URL: "/settings", Mode: config.SeedModeHistory}, true, "https://app.test/settings"},
		{"absolute fragment route keeps its page", config.ExtraSeed{URL: "https://app.test/other/#/a/:b"}, false, "https://app.test/other/#/a/1"},
		{"other origin hashes at its root", config.ExtraSeed{URL: "https://cdn.app.test/x", Mode: config.SeedModeHash}, false, "https://cdn.app.test/#/x"},
	}
	for _, tc := range cases {
		got, ok := ResolveExtraSeed(start, tc.seed, tc.hashApp)
		if !ok || got != tc.want {
			t.Errorf("%s: ResolveExtraSeed(%+v, hashApp=%v) = %q, %v; want %q", tc.name, tc.seed, tc.hashApp, got, ok, tc.want)
		}
	}
	// An ordinary anchor is not a route: the seed is the start page itself.
	if got, _ := ResolveExtraSeed(start, config.ExtraSeed{URL: "#section-2"}, false); strings.Contains(got, "section-2") {
		t.Errorf("in-page anchor resolved to %q", got)
	}
}

func TestSelectExtraSeedsScopeDedupPriorityAndCap(t *testing.T) {
	start := mustURL(t, "https://app.test/")
	seeds := []config.ExtraSeed{
		{URL: "/low", Priority: 1},
		{URL: "/users/:id", Priority: 5},
		{URL: "/users/42", Priority: 4},               // same shape as /users/1
		{URL: "/sitemap-page", Priority: 9},           // already declared
		{URL: "https://evil.test/admin", Priority: 9}, // out of scope
		{URL: "/", Priority: 8},                       // the landing page itself
		{URL: "#/dash", Priority: 3},                  // hash route, distinct from /
		{URL: "/files/*", Priority: 10},               // not concrete
		{URL: "/admin/reports/:reportId", Priority: 6},
	}
	inScope := func(raw string) bool { return strings.HasPrefix(raw, "https://app.test/") }
	declared := []string{"https://app.test/sitemap-page"}

	got := selectExtraSeeds(seeds, start, "https://app.test/", declared, 10, inScope)
	want := []string{
		"https://app.test/admin/reports/1",
		"https://app.test/users/1",
		"https://app.test/#/dash",
		"https://app.test/low",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("selectExtraSeeds = %v\nwant %v", got, want)
	}
	if capped := selectExtraSeeds(seeds, start, "https://app.test/", declared, 2, inScope); !reflect.DeepEqual(capped, want[:2]) {
		t.Fatalf("cap 2 = %v, want %v", capped, want[:2])
	}
	if none := selectExtraSeeds(seeds, start, "", nil, 0, inScope); none != nil {
		t.Fatalf("cap 0 must select nothing, got %v", none)
	}
}

func TestSelectExtraSeedsFollowsHashRoutedLanding(t *testing.T) {
	start := mustURL(t, "https://app.test/")
	got := selectExtraSeeds([]config.ExtraSeed{{URL: "/inbox/:id"}}, start, "https://app.test/#/home", nil, 5, nil)
	if want := []string{"https://app.test/#/inbox/1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("hash-routed landing: got %v, want %v", got, want)
	}
}
