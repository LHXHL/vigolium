package discovery

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
)

func routeFact(path string, fullPath *string, extractor string) *jstangle.ClientRouteFact {
	route := &jstangle.ClientRouteFact{
		Kind: "clientRoute", Path: jstangle.ValueTemplate{Rendered: path, Static: true}, RouteType: "page",
		Provenance: jstangle.Provenance{Extractor: extractor, Confidence: "high"},
	}
	if fullPath != nil {
		route.FullPath = &jstangle.ValueTemplate{Rendered: *fullPath, Static: true}
	}
	return route
}

func TestClientRouteSeedPrefersFullPath(t *testing.T) {
	full := "/admin/reports/:reportId"
	got, ok := clientRouteSeed(routeFact(":reportId", &full, "router-config"))
	if !ok || got != "/admin/reports/1" {
		t.Fatalf("clientRouteSeed = %q, %v; want /admin/reports/1", got, ok)
	}
}

// An older helper reports Angular children without a leading slash and with
// no fullPath. They used to be dropped; now they are kept under "/".
func TestClientRouteSeedPrefixesBareRouterConfigPathWithoutFullPath(t *testing.T) {
	got, ok := clientRouteSeed(routeFact("dashboard", nil, "router-config"))
	if !ok || got != "/dashboard" {
		t.Fatalf("clientRouteSeed = %q, %v; want /dashboard", got, ok)
	}
	if got, ok := clientRouteSeed(routeFact("edit", nil, "router-navigation")); ok {
		t.Fatalf("relative navigation must not be guessed absolute, got %q", got)
	}
}

func TestClientRouteSeedRejectsUnresolvedParent(t *testing.T) {
	full := "${parent}/profile"
	route := routeFact("profile", &full, "router-config")
	route.FullPath.Static = false
	if got, ok := clientRouteSeed(route); ok {
		t.Fatalf("a route under an unknown parent must not be seeded, got %q", got)
	}
}

func TestPathLiteralSeed(t *testing.T) {
	cases := []struct {
		name    string
		fact    jstangle.PathLiteralFact
		path    string
		trusted bool
		ok      bool
	}{
		{"api path", jstangle.PathLiteralFact{Value: jstangle.ValueTemplate{Rendered: "/api/v2/profile", Static: true}, Key: "profile"}, "/api/v2/profile", true, true},
		{"url key", jstangle.PathLiteralFact{Value: jstangle.ValueTemplate{Rendered: "/help/index.html", Static: true}, Key: "helpUrl"}, "/help/index.html", true, true},
		{"plain hint", jstangle.PathLiteralFact{Value: jstangle.ValueTemplate{Rendered: "/account/settings", Static: true}, Key: "sitemap"}, "/account/settings", false, true},
		{"template", jstangle.PathLiteralFact{Value: jstangle.ValueTemplate{Rendered: "/items/${id}", Static: false}}, "", false, false},
		{"protocol relative", jstangle.PathLiteralFact{Value: jstangle.ValueTemplate{Rendered: "//cdn.test/x", Static: true}}, "", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, trusted, ok := pathLiteralSeed(&tc.fact)
			if path != tc.path || trusted != tc.trusted || ok != tc.ok {
				t.Fatalf("pathLiteralSeed = %q, %v, %v; want %q, %v, %v", path, trusted, ok, tc.path, tc.trusted, tc.ok)
			}
		})
	}
}
