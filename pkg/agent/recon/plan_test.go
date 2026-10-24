package recon

import (
	"net/http"
	"strings"
	"testing"
)

func methodsIn(reqs []ProbeRequest) map[string]bool {
	out := map[string]bool{}
	for _, r := range reqs {
		out[r.Method] = true
	}
	return out
}

// Every planned request is a read, at every depth.
func TestPlanSendsOnlyReads(t *testing.T) {
	for _, d := range []Depth{DepthLight, DepthStandard, DepthFull} {
		reqs := Plan(d)
		for m := range methodsIn(reqs) {
			switch m {
			case http.MethodGet, http.MethodOptions, http.MethodPost:
			default:
				t.Errorf("depth %s plans a %s", d, m)
			}
		}
		for _, r := range reqs {
			if r.Method == http.MethodPost && r.Kind != KindGraphQL {
				t.Errorf("depth %s: only the introspection query may POST, got %s %s", d, r.Kind, r.Path)
			}
		}
	}
	if n := len(Plan(DepthLight)); n > 9 {
		t.Errorf("light depth plans %d requests, want about nine with the icon", n)
	}
	if len(Plan(DepthStandard)) <= len(Plan(DepthLight)) || len(Plan(DepthFull)) <= len(Plan(DepthStandard)) {
		t.Error("each depth adds to the one below it")
	}
}

func obs(kind ProbeKind, path string, status int, headers map[string]string, body string) Observation {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return Observation{Req: ProbeRequest{Kind: kind, Method: http.MethodGet, Path: path}, URL: "https://h.example" + path,
		Status: status, Headers: h, Body: body, Proto: "HTTP/2.0"}
}

func TestPlanFollowUpUsesTheLinkedIcon(t *testing.T) {
	first := []Observation{obs(KindBase, "/", 200, nil,
		`<html><head><link rel="shortcut icon" href="/static/i.png?v=2"><script src="/app.js"></script></head></html>`)}
	reqs := PlanFollowUp("https://h.example", DepthFull, first)
	var fav, maps []string
	for _, r := range reqs {
		switch r.Kind {
		case KindFavicon:
			fav = append(fav, r.Path)
		case KindSourceMap:
			maps = append(maps, r.Path)
		}
	}
	if len(fav) != 1 || fav[0] != "/static/i.png?v=2" {
		t.Errorf("favicon path = %v", fav)
	}
	if len(maps) != 1 || maps[0] != "/app.js.map" {
		t.Errorf("source maps = %v", maps)
	}

	// No link: /favicon.ico. A cross-origin link is not followed.
	first = []Observation{obs(KindBase, "/", 200, nil, `<link rel="icon" href="https://cdn.example/i.png">`)}
	for _, r := range PlanFollowUp("https://h.example", DepthLight, first) {
		if r.Kind == KindFavicon && r.Path != "/favicon.ico" {
			t.Errorf("cross-origin icon followed: %s", r.Path)
		}
	}
}

func TestAnalyzeReadsEachKind(t *testing.T) {
	icon := "\x89PNG\r\n\x1a\nrest"
	o := []Observation{
		obs(KindBase, "/", 200, map[string]string{"Server": "nginx/1.25.3", "X-Powered-By": "Express", "Alt-Svc": `h3=":443"`},
			`<html><title> Acme  Portal </title><form action="/login"><input name="email"><input type="password" name="pw"></form></html>`),
		obs(KindWellKnown, "/robots.txt", 200, map[string]string{"Content-Type": "text/plain"}, "User-agent: *\nDisallow: /admin"),
		obs(KindWellKnown, "/.well-known/security.txt", 404, nil, ""),
		obs(KindFavicon, "/favicon.ico", 200, nil, icon),
		obs(KindOptions, "/", 204, map[string]string{"Allow": "GET, HEAD, OPTIONS"}, ""),
		obs(KindCORS, "/", 204, map[string]string{"Access-Control-Allow-Origin": corsTestOrigin, "Access-Control-Allow-Credentials": "true"}, ""),
		obs(KindSourceMap, "/app.js.map", 200, nil, `{"version":3,"mappings":"AAAA"}`),
		{Req: ProbeRequest{Kind: KindNotFound, Path: "/x"}, Err: errTest},
	}
	vh := obs(KindVHost, "/", 403, nil, "denied")
	vh.Req.Host = "localhost"
	o = append(o, vh)

	r := Analyze("https://h.example", o)
	if r.Title != "Acme Portal" || r.Server != "nginx/1.25.3" || r.PoweredBy != "Express" || r.HTTPVersion != "HTTP/2.0" {
		t.Errorf("base facts: %+v", r)
	}
	if len(r.WellKnown) != 1 || r.WellKnown[0].Path != "/robots.txt" || !strings.Contains(r.WellKnown[0].Snippet, "Disallow") {
		t.Errorf("well-known: %+v", r.WellKnown)
	}
	if r.Favicon == nil || r.Favicon.MMH3 != ShodanFaviconHash([]byte(icon)) || r.FaviconHash != r.Favicon.MD5 {
		t.Errorf("favicon: %+v", r.Favicon)
	}
	if got := r.AllowedMethods["/"]; len(got) != 3 {
		t.Errorf("allowed methods: %v", r.AllowedMethods)
	}
	if r.CORS == nil || !r.CORS.Reflective {
		t.Errorf("cors: %+v", r.CORS)
	}
	if len(r.SourceMaps) != 1 {
		t.Errorf("source maps: %v", r.SourceMaps)
	}
	if len(r.VHostFindings) != 1 || r.VHostFindings[0].StatusCode != 403 {
		t.Errorf("vhost: %+v", r.VHostFindings)
	}
	if len(r.LoginCandidates) != 1 || r.LoginCandidates[0].PasswordName != "pw" {
		t.Errorf("login: %+v", r.LoginCandidates)
	}
	if r.ProbeCount != len(o) || r.ProbeErrors != 1 {
		t.Errorf("counts: %d probes, %d errors", r.ProbeCount, r.ProbeErrors)
	}

	// A soft-404 HTML page at /favicon.ico is not hashed.
	soft := Analyze("https://h.example", []Observation{obs(KindFavicon, "/favicon.ico", 200, nil, "<html>not found</html>")})
	if soft.Favicon != nil {
		t.Errorf("an HTML favicon response was hashed")
	}
}

type testErr string

func (e testErr) Error() string { return string(e) }

const errTest = testErr("connection refused")

// On an origin that answers 200 for every path, a path is reachable only when
// it does not look like that answer.
func TestAnalyzeDiscountsSoftNotFound(t *testing.T) {
	soft := `<html><head><title>Page not found</title></head><body>Sorry, nothing here.</body></html>`
	nf := func(p string) Observation {
		o := obs(KindNotFound, p, 200, nil, soft)
		return o
	}
	stack := obs(KindStack, "/actuator", 200, nil, soft)
	stack.Req.Meta = "0"
	real := obs(KindStack, "/wp-login.php", 200, nil, `<html><title>Log In</title><form><input type="password"></form></html>`)
	real.Req.Meta = "5"
	wk := obs(KindWellKnown, "/sitemap.xml", 200, nil, soft)
	r := Analyze("https://h.example", []Observation{
		obs(KindBase, "/", 200, nil, "<html><title>Home</title></html>"),
		nf("/a1"), nf("/b2"), nf("/c3/d4"), stack, real, wk,
	})
	if len(r.WellKnown) != 0 {
		t.Errorf("a soft-404 sitemap was reported: %+v", r.WellKnown)
	}
	if len(r.Stacks) != 1 || r.Stacks[0].Name != "wordpress" {
		t.Errorf("stacks = %+v, want only wordpress", r.Stacks)
	}
}
