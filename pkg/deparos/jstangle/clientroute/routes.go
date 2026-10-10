// Package clientroute turns client-side router paths (jstangle clientRoute
// facts) into concrete, navigable paths. Content discovery requests a route as
// a path and the browser crawl navigates to it; both go through this package so
// "/users/:id" becomes the same "/users/1" in each.
//
// It is a leaf package on purpose: the crawler imports it, and the jstangle
// package itself carries the embedded helper binaries.
package clientroute

import (
	"regexp"
	"strings"
)

var (
	colonParam   = regexp.MustCompile(`(^|/):[A-Za-z_][A-Za-z0-9_]*[?+*]?`)
	bracketParam = regexp.MustCompile(`\[\[?\.\.\.[^]]+\]\]?|\[[^]]+\]`)
	braceParam   = regexp.MustCompile(`\$?\{[^}]+\}`)
)

// Stable substitutes a route's parameters with a placeholder value ("1") so
// the route names one concrete location: ":id" (Express/React/Vue/Angular),
// "[id]" and "[...slug]" (Next.js), "{id}" and "${id}" (templated). Wildcard
// routes, routes that are not rooted at "/", and anything left with
// unresolved pattern syntax are refused.
func Stable(raw string) (string, bool) {
	route := strings.TrimSpace(raw)
	if !strings.HasPrefix(route, "/") || strings.Contains(route, "*") || strings.Contains(route, "${") && !braceParam.MatchString(route) {
		return "", false
	}
	route = colonParam.ReplaceAllString(route, `${1}1`)
	route = bracketParam.ReplaceAllString(route, "1")
	route = braceParam.ReplaceAllString(route, "1")
	if strings.ContainsAny(route, "[]{}*") {
		return "", false
	}
	return route, true
}

// SeedPath is the concrete path of one route fact. fullPath is the helper's
// normalized route (parents joined, leading "/") when it reported one, else "".
// An older helper reports Angular/Vue child routes bare ("dashboard"); for a
// router-config route without fullPath a leading "/" is added, which loses the
// parent but beats discarding the route.
func SeedPath(path, fullPath, extractor string) (string, bool) {
	raw := strings.TrimSpace(fullPath)
	if raw == "" {
		raw = strings.TrimSpace(path)
		if extractor == "router-config" && raw != "" && !strings.HasPrefix(raw, "/") &&
			!strings.HasPrefix(raw, "$") && !strings.Contains(raw, "://") {
			raw = "/" + raw
		}
	}
	return Stable(raw)
}

// Skip reports whether a route fact is no navigation target: a redirect entry
// (it only points at another route) or a low-confidence guess.
func Skip(routeType, confidence string) bool {
	return routeType == "redirect" || confidence == "low"
}

// HashRoute splits a URL fragment that carries a client route into its prefix
// and route path: "/users/1" gives ("", "/users/1"), and the AngularJS
// hashbang "!/users/1" gives ("!", "/users/1"). ok is false for an ordinary
// in-page anchor ("section-2").
func HashRoute(fragment string) (prefix, path string, ok bool) {
	switch {
	case strings.HasPrefix(fragment, "/"):
		return "", fragment, true
	case strings.HasPrefix(fragment, "!/"):
		return "!", fragment[1:], true
	}
	return "", "", false
}
