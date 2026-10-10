package runner

import (
	neturl "net/url"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
)

func appRoute(path string) database.ClientRoute {
	return database.ClientRoute{Scheme: "https", Hostname: "app.x.com", Port: 443, Path: path,
		RouteType: "page", Extractor: "react-router-jsx", Confidence: "high"}
}

func TestRouteSeedPathFiltersAndNormalizes(t *testing.T) {
	nested := appRoute(":reportId")
	nested.Extractor, nested.FullPath, nested.FullPathStatic = "router-config", "/admin/reports/:reportId", true
	bare := appRoute("dashboard")
	bare.Extractor = "router-config"
	crossModule := appRoute(":id")
	crossModule.FullPath, crossModule.FullPathStatic = "${parent}/:id", false
	redirect := appRoute("/old")
	redirect.RouteType = "redirect"
	low := appRoute("/guess")
	low.Confidence = "low"
	api := appRoute("/api/items")
	api.RouteType = "api"

	cases := []struct {
		name  string
		route database.ClientRoute
		want  string
		ok    bool
	}{
		{"nested fullPath", nested, "/admin/reports/1", true},
		{"bare router-config child", bare, "/dashboard", true},
		{"jsx param route", appRoute("/users/:id"), "/users/1", true},
		{"parent in another module", crossModule, "", false},
		{"redirect", redirect, "", false},
		{"low confidence", low, "", false},
		{"api route", api, "", false},
		{"wildcard", appRoute("/files/*"), "", false},
	}
	for _, tc := range cases {
		got, ok := routeSeedPath(tc.route)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: routeSeedPath = %q, %v; want %q, %v", tc.name, got, ok, tc.want, tc.ok)
		}
	}

	odd := appRoute("/console")
	odd.Scheme, odd.Port = "http", 8080
	if u, ok := routeSeedURL(odd); !ok || u.String() != "http://app.x.com:8080/console" {
		t.Errorf("routeSeedURL(non-default port) = %v, %v", u, ok)
	}
}

// TestSelectReSpiderSeeds_MixedRecordAndRouteSeeds: client-route candidates
// share the route dedup and both caps with record-derived ones, skip the shell
// dedup (they have no response), and are dropped when the spider already
// reached their route template or when they look like a login screen.
func TestSelectReSpiderSeeds_MixedRecordAndRouteSeeds(t *testing.T) {
	rows := []database.ReSpiderCandidate{
		// The spider already crawled shell one at the root and at /users/7.
		htmlRow("spidering", "app.x.com", "https://app.x.com/", 200, shellOne),
		htmlRow("spidering", "app.x.com", "https://app.x.com/users/7", 200, shellOne),
		// Discovery found a new shell at /admin/.
		htmlRow("deparos", "app.x.com", "https://app.x.com/admin/", 200, shellTwo),
	}
	evals := make([]respiderEvaluated, 0, len(rows)+8)
	for i := range rows {
		evals = append(evals, reduceReSpiderRow(&rows[i]))
	}
	other := appRoute("/settings/profile")
	other.Hostname = "other.x.com"
	evals = append(evals, routeEvaluated([]database.ClientRoute{
		appRoute("/reports/:reportId"), // new route, same SPA shell: kept
		appRoute("/reports/42"),        // same template as /reports/1: dup-route
		appRoute("/users/:id"),         // the spider reached /users/7: dup-route
		appRoute("/login"),             // a login screen: skipped
		appRoute("/admin/"),            // the record seed already holds this route
		appRoute("/billing"),           // kept, but past the per-host cap
		other,                          // another host: its own cap
	})...)

	chosen, skips, kept := selectReSpiderSeedsFromEvaluated(evals, 2, 10)
	if kept != 4 {
		t.Fatalf("kept = %d, want 4 (/admin/ record, /reports/1, /billing, other host)", kept)
	}
	if skips["dup-route"] != 3 || skips["login"] != 1 || skips["dup-shell"] != 0 {
		t.Errorf("skips = %v, want dup-route=3 login=1 and no dup-shell", skips)
	}
	urls := chosenURLs(chosen)
	if len(chosen) != 3 || !urls["https://app.x.com/admin/"] || !urls["https://app.x.com/reports/1"] || !urls["https://other.x.com/settings/profile"] {
		t.Fatalf("chosen = %v, want /admin/ + /reports/1 on app.x.com (per-host cap 2) and the other host's route", urls)
	}
	routeSeeds := 0
	for _, s := range chosen {
		if s.source == routeSeedSource {
			routeSeeds++
		}
	}
	if routeSeeds != 2 || routeSeedNote(chosen) == "" {
		t.Errorf("route seeds chosen = %d (note %q), want 2", routeSeeds, routeSeedNote(chosen))
	}

	if capped, _, _ := selectReSpiderSeedsFromEvaluated(evals, 2, 1); len(capped) != 1 {
		t.Errorf("total cap 1 chose %d", len(capped))
	}
}

func TestNewRouteSeedSetGroupsRanksAndCaps(t *testing.T) {
	other := appRoute("/inbox")
	other.Hostname = "mail.x.com"
	set := newRouteSeedSet([]database.ClientRoute{
		appRoute("/about"),
		appRoute("/admin/users/:id"),
		appRoute("/admin/users/9"), // same template
		appRoute("/dashboard"),
		appRoute("/login"), // login screen
		other,
	}, 2)
	if set.count() != 3 {
		t.Fatalf("count = %d, want 3 (2 for app.x.com after the cap, 1 for mail.x.com)", set.count())
	}
	app := set.forTarget("https://app.x.com/start")
	if len(app) != 2 || app[0].URL != "https://app.x.com/admin/users/1" || app[1].URL != "https://app.x.com/dashboard" {
		t.Fatalf("app.x.com seeds = %+v, want admin then dashboard (ranked by path keywords)", app)
	}
	if app[0].Source != routeSeedSource || app[0].Priority <= app[1].Priority {
		t.Errorf("seed metadata = %+v", app)
	}
	if got := set.forTarget("https://mail.x.com/"); len(got) != 1 {
		t.Errorf("mail.x.com seeds = %+v", got)
	}
	if set.forTarget("") != nil || set.forTarget("https://none.x.com/") != nil {
		t.Error("unknown hosts and the re-spider's empty target get no seeds")
	}
	var nilSet *routeSeedSet
	if nilSet.forTarget("https://app.x.com/") != nil || nilSet.count() != 0 {
		t.Error("a nil set must be inert")
	}
	if newRouteSeedSet([]database.ClientRoute{appRoute("/login")}, 5) != nil {
		t.Error("a set with no usable route must be nil")
	}
}

func TestCanonicalRouteKeepsHashRoutesApart(t *testing.T) {
	key := func(raw string) string {
		u, err := neturl.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return canonicalRoute(u)
	}
	if key("https://a.x.com/#/users/1") != key("https://a.x.com/#/users/2") {
		t.Error("hash routes of one template must share a key")
	}
	if key("https://a.x.com/#/users/1") == key("https://a.x.com/#/settings") || key("https://a.x.com/#/settings") == key("https://a.x.com/") {
		t.Error("distinct hash routes must not collapse onto each other or the page")
	}
	if key("https://a.x.com/page#section") != key("https://a.x.com/page") {
		t.Error("an in-page anchor is not a route")
	}
}
