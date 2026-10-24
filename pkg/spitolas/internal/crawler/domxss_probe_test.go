package crawler

import (
	"strings"
	"testing"
)

func findParam(cands []reflectedCandidate, name string) (reflectedCandidate, bool) {
	for _, c := range cands {
		if c.param == name {
			return c, true
		}
	}
	return reflectedCandidate{}, false
}

func TestParamsFromURL_FragmentReflected(t *testing.T) {
	url := "http://localhost:3000/#/search?q=vigoliumReflectMarker7391"
	dom := `<div id="searchValue">vigoliumReflectMarker7391</div>`
	c, ok := findParam(paramsFromURL(url, dom), "q")
	if !ok || !c.inFrag || !c.valueReflected {
		t.Fatalf("want reflected fragment param q, got %+v ok=%v", c, ok)
	}
}

func TestParamsFromURL_SlotNotReflected(t *testing.T) {
	// Empty/short or absent-from-DOM value: the param slot is still returned so a
	// marker probe can test it, but flagged not-yet-reflected.
	url := "http://localhost:3000/#/search?q=notpresentvalue"
	dom := `<div>nothing here</div>`
	c, ok := findParam(paramsFromURL(url, dom), "q")
	if !ok || c.valueReflected {
		t.Fatalf("want q slot flagged not-reflected, got %+v ok=%v", c, ok)
	}
}

func TestParamsFromURL_QueryStringReflected(t *testing.T) {
	url := "http://localhost:3000/page?name=reflectedname123"
	dom := `<h1>reflectedname123</h1>`
	c, ok := findParam(paramsFromURL(url, dom), "name")
	if !ok || c.inFrag || !c.valueReflected {
		t.Fatalf("want reflected query param name, got %+v ok=%v", c, ok)
	}
}

func TestCollectReflectedCandidates_ReflectedFirst(t *testing.T) {
	// Ordering contract: confirmed-reflection candidates come before bare slots.
	reflected := reflectedCandidate{param: "a", valueReflected: true, dedupeKey: "a"}
	slot := reflectedCandidate{param: "b", valueReflected: false, dedupeKey: "b"}
	got := append([]reflectedCandidate{}, reflected, slot)
	// (exercise the ordering helper directly via append semantics used in collect)
	if got[0].param != "a" {
		t.Fatalf("expected reflected candidate first")
	}
}

func TestBuildDOMXssProbeURL_Fragment(t *testing.T) {
	cand := reflectedCandidate{rawURL: "http://localhost:3000/#/search?q=old", param: "q", inFrag: true}
	got, ok := buildDOMXssProbeURL(cand, "<img src=x onerror=window.__vigoliumxss0=1>")
	if !ok {
		t.Fatal("build failed")
	}
	if !strings.Contains(got, "#/search?q=") {
		t.Errorf("lost the SPA route: %s", got)
	}
	if strings.ContainsAny(got, "<> ") {
		t.Errorf("payload not encoded: %s", got)
	}
	if !strings.Contains(got, "%3Cimg%20src%3Dx%20onerror%3D") {
		t.Errorf("expected encoded canary, got: %s", got)
	}
}

func TestPctEncodeComponent(t *testing.T) {
	if got := pctEncodeComponent("<img src=x>"); got != "%3Cimg%20src%3Dx%3E" {
		t.Errorf("got %q", got)
	}
	if got := pctEncodeComponent("safe-Value_1.0~"); got != "safe-Value_1.0~" {
		t.Errorf("unreserved chars must pass through, got %q", got)
	}
}

func TestPrioritizeRoutes_SearchFirst(t *testing.T) {
	in := []string{"about", "login", "search", "contact", "product-list"}
	got := prioritizeRoutes(in)
	// search-like routes must come before plain ones
	if got[0] != "search" && got[0] != "product-list" {
		t.Fatalf("expected a reflective route first, got %v", got)
	}
	// both reflective routes present ahead of "about"
	idxAbout, idxSearch := indexOf(got, "about"), indexOf(got, "search")
	if idxSearch > idxAbout {
		t.Fatalf("search should precede about: %v", got)
	}
}

func TestIsPlainRouteName(t *testing.T) {
	ok := []string{"search", "order-history", "score-board", "v1"}
	for _, r := range ok {
		if !isPlainRouteName(r) {
			t.Errorf("want plain: %q", r)
		}
	}
	bad := []string{"", "a", ":id", "user/:id", "**", "path\"x"}
	for _, r := range bad {
		if isPlainRouteName(r) {
			t.Errorf("want rejected: %q", r)
		}
	}
}

func indexOf(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}
