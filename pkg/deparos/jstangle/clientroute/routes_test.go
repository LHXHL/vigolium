package clientroute

import "testing"

func TestStableBoundsDynamicAndWildcardRoutes(t *testing.T) {
	cases := map[string]string{
		"/users/:id":       "/users/1",
		"/org/[org]/users": "/org/1/users",
		"/post/${slug}":    "/post/1",
		"/docs/[...slug]":  "/docs/1",
		"/a/:id?/b":        "/a/1/b",
		"/plain":           "/plain",
	}
	for input, want := range cases {
		got, ok := Stable(input)
		if !ok || got != want {
			t.Errorf("Stable(%q) = %q, %v; want %q", input, got, ok, want)
		}
	}
	for _, input := range []string{"*", "/*", "/files/:path*", "https://other.test/page", "users", ""} {
		if got, ok := Stable(input); ok {
			t.Errorf("wildcard/non-root route %q unexpectedly became %q", input, got)
		}
	}
}

func TestSeedPathPrefersFullPathAndRootsBareRouterConfigChildren(t *testing.T) {
	cases := []struct {
		path, fullPath, extractor string
		want                      string
		ok                        bool
	}{
		{":reportId", "/admin/reports/:reportId", "router-config", "/admin/reports/1", true},
		{"dashboard", "", "router-config", "/dashboard", true},
		{"edit", "", "router-navigation", "", false},
		{"/users/:id", "", "react-router-jsx", "/users/1", true},
		{"${base}/x", "", "router-config", "", false},
	}
	for _, tc := range cases {
		got, ok := SeedPath(tc.path, tc.fullPath, tc.extractor)
		if got != tc.want || ok != tc.ok {
			t.Errorf("SeedPath(%q, %q, %q) = %q, %v; want %q, %v", tc.path, tc.fullPath, tc.extractor, got, ok, tc.want, tc.ok)
		}
	}
}

func TestSkipAndHashRoute(t *testing.T) {
	if !Skip("redirect", "high") || !Skip("page", "low") || Skip("page", "medium") {
		t.Error("Skip must drop redirects and low-confidence routes only")
	}
	for frag, want := range map[string][2]string{"/users/1": {"", "/users/1"}, "!/users/1": {"!", "/users/1"}} {
		prefix, path, ok := HashRoute(frag)
		if !ok || prefix != want[0] || path != want[1] {
			t.Errorf("HashRoute(%q) = %q, %q, %v", frag, prefix, path, ok)
		}
	}
	for _, frag := range []string{"", "top", "section-2", "!"} {
		if _, _, ok := HashRoute(frag); ok {
			t.Errorf("HashRoute(%q) must not be a route", frag)
		}
	}
}
