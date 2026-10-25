package recon

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// A planned recon pass is split into what to ask, how to send it, and what the
// answers mean, so the transport is the caller's:
//
//   - Plan lists the first round of requests for an origin; PlanFollowUp lists
//     the second round, which depends on the first (the icon the page links, the
//     paths that answered, the base response vhosts are compared against).
//   - The caller puts them on the wire. The CLI fingerprint phase sends through
//     the scan executor, so scope admission, rate limits, the request budget and
//     WAF pacing apply, and every request is stored as an http_record.
//   - Analyze turns the observations into a TechStackReport. It sends nothing.
//
// Every planned request is a read: GET, OPTIONS, and one GraphQL introspection
// POST that queries the schema.

// ProbeKind says what a probe's answer feeds.
type ProbeKind string

// Probe kinds.
const (
	KindBase      ProbeKind = "base"       // GET / — headers, cookies, body fingerprints, security headers
	KindAPISpec   ProbeKind = "api-spec"   // an API definition path; Meta is its kind
	KindGraphQL   ProbeKind = "graphql"    // a GraphQL introspection query
	KindWellKnown ProbeKind = "well-known" // robots, sitemap, security.txt, openid-configuration, …
	KindStack     ProbeKind = "stack"      // a path whose reachability names a stack; Meta indexes stackProbePaths
	KindSensitive ProbeKind = "sensitive"  // a path that should not be reachable; Meta is the reason
	KindOptions   ProbeKind = "options"    // OPTIONS, for the Allow header
	KindCORS      ProbeKind = "cors"       // a preflight from a foreign Origin
	KindFavicon   ProbeKind = "favicon"    // the icon the page links, or /favicon.ico
	KindVHost     ProbeKind = "vhost"      // GET / with a different Host header
	KindNotFound  ProbeKind = "not-found"  // a random path, for the host's not-found baseline
	KindSourceMap ProbeKind = "source-map" // a script's .map, or the map a response header names
)

// Depth selects how much of the plan runs.
type Depth string

// Depths, cheapest first.
const (
	// DepthLight is about nine requests per origin: the base page, its icon,
	// robots.txt, security.txt, the OpenID configuration, three random paths
	// for the not-found baseline, and a CORS preflight.
	DepthLight Depth = "light"
	// DepthStandard adds every well-known path, API-definition paths, GraphQL
	// introspection, stack paths, OPTIONS on / and /api, and vhost variants.
	DepthStandard Depth = "standard"
	// DepthFull adds sensitive-file paths, OPTIONS on every path that answered,
	// and source maps for the page's same-origin scripts.
	DepthFull Depth = "full"
)

// ParseDepth validates a depth name; "" is DepthStandard.
func ParseDepth(s string) (Depth, bool) {
	switch Depth(strings.ToLower(strings.TrimSpace(s))) {
	case "", DepthStandard:
		return DepthStandard, true
	case DepthLight:
		return DepthLight, true
	case DepthFull:
		return DepthFull, true
	}
	return "", false
}

// ProbeRequest is one request a recon pass sends to an origin.
type ProbeRequest struct {
	Kind   ProbeKind
	Method string
	// Path is the request target off the origin root ("/robots.txt").
	Path string
	// Host overrides the Host header (vhost probes); "" keeps the origin's.
	Host string
	// Headers are sent in addition to the sender's defaults.
	Headers map[string]string
	Body    string
	// Meta is kind-specific (an API definition's kind, a stack path's index,
	// a sensitive path's reason).
	Meta string
}

// Observation is one probe and what came back. Err is set when nothing did.
type Observation struct {
	Req     ProbeRequest
	URL     string
	Status  int
	Headers http.Header
	Body    string
	// Proto is the response's protocol ("HTTP/1.1", "HTTP/2.0").
	Proto string
	// Truncated reports a body cut short by the sender's cap; such a body is
	// not hashed (a favicon hash over a prefix matches nothing).
	Truncated bool
	Err       error
	// ErrKind classifies Err as one of the ProbeErr* kinds; "" with Err set is
	// ProbeErrNetwork.
	ErrKind string
}

// Follow-up bounds, exported so a caller can budget a pass without restating
// them: vhostVariants yields at most MaxVHostVariants Host headers, and a full
// pass asks OPTIONS of at most MaxOptionsPaths answered paths ("/" included)
// and fetches at most MaxSourceMaps maps.
const (
	MaxVHostVariants = 3
	MaxOptionsPaths  = 8
	MaxSourceMaps    = 5
)

// corsTestOrigin is the foreign Origin the CORS preflight presents.
const corsTestOrigin = "https://recon-probe.invalid"

// lightWellKnown is the well-known subset DepthLight fetches.
var lightWellKnown = []string{"/robots.txt", "/.well-known/security.txt", "/.well-known/openid-configuration"}

// Plan returns the first round of probes for an origin.
func Plan(depth Depth) []ProbeRequest {
	if depth == "" {
		depth = DepthStandard
	}
	get := func(kind ProbeKind, path, meta string) ProbeRequest {
		return ProbeRequest{Kind: kind, Method: http.MethodGet, Path: path, Meta: meta}
	}
	reqs := []ProbeRequest{get(KindBase, "/", "")}

	if depth == DepthLight {
		for _, p := range lightWellKnown {
			reqs = append(reqs, get(KindWellKnown, p, ""))
		}
	} else {
		for _, p := range wellKnownPaths {
			reqs = append(reqs, get(KindWellKnown, p, ""))
		}
		for _, s := range apiSpecPaths {
			reqs = append(reqs, get(KindAPISpec, s.Path, s.Kind))
		}
		for _, p := range graphqlProbePaths {
			reqs = append(reqs, ProbeRequest{Kind: KindGraphQL, Method: http.MethodPost, Path: p,
				Headers: map[string]string{"Content-Type": "application/json", "Accept": "application/json"},
				Body:    `{"query":"{__schema{types{name}}}"}`})
		}
		for i, sp := range stackProbePaths {
			reqs = append(reqs, get(KindStack, sp.Path, strconv.Itoa(i)))
		}
		for _, p := range optionsProbePaths {
			reqs = append(reqs, ProbeRequest{Kind: KindOptions, Method: http.MethodOptions, Path: p})
		}
	}
	if depth == DepthFull {
		for _, sp := range sensitivePaths {
			reqs = append(reqs, get(KindSensitive, sp.Path, sp.Reason))
		}
	}
	reqs = append(reqs, ProbeRequest{Kind: KindCORS, Method: http.MethodOptions, Path: "/",
		Headers: map[string]string{"Origin": corsTestOrigin, "Access-Control-Request-Method": "GET"}})
	for _, p := range randomNotFoundPaths() {
		reqs = append(reqs, get(KindNotFound, p, ""))
	}
	return reqs
}

// randomNotFoundPaths returns three paths no application serves — the fewest a
// stable signature can be learned from (deparos/fingerprint.NewSignature).
func randomNotFoundPaths() []string {
	return []string{"/" + randomHex(12), "/" + randomHex(14), "/" + randomHex(12) + "/" + randomHex(8)}
}

func randomHex(n int) string {
	b := make([]byte, n/2+1)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

// PlanFollowUp returns the second round, which depends on the first: the icon
// the base page links, vhost variants compared against the base response, and
// at DepthFull OPTIONS on the paths that answered and the page's source maps.
func PlanFollowUp(baseURL string, depth Depth, first []Observation) []ProbeRequest {
	if depth == "" {
		depth = DepthStandard
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Host == "" {
		return nil
	}
	base := baseObservation(first)
	var basePage string
	if base != nil {
		basePage = base.Body
	}

	reqs := []ProbeRequest{FaviconRequest(parsed, basePage)}
	if depth != DepthLight && base != nil {
		for _, v := range vhostVariants(parsed.Host) {
			reqs = append(reqs, ProbeRequest{Kind: KindVHost, Method: http.MethodGet, Path: "/", Host: v})
		}
	}
	if depth == DepthFull {
		seen := map[string]bool{}
		for _, p := range optionsProbePaths {
			seen[p] = true
		}
		for _, p := range reachablePaths(first, MaxOptionsPaths) {
			if !seen[p] {
				seen[p] = true
				reqs = append(reqs, ProbeRequest{Kind: KindOptions, Method: http.MethodOptions, Path: p})
			}
		}
		if base != nil {
			for _, p := range sourceMapPaths(parsed, base) {
				reqs = append(reqs, ProbeRequest{Kind: KindSourceMap, Method: http.MethodGet, Path: p})
			}
		}
	}
	return reqs
}

func baseObservation(obs []Observation) *Observation {
	for i := range obs {
		if obs[i].Req.Kind == KindBase && obs[i].Err == nil {
			return &obs[i]
		}
	}
	return nil
}

var iconLinkRE = regexp.MustCompile(`(?is)<link\b[^>]*\brel\s*=\s*["'][^"']*\bicon\b[^"']*["'][^>]*>`)

// FaviconRequest is the read that fetches an origin's icon: the same-origin
// icon the origin's page links, or /favicon.ico when page is "" or links none.
// The fingerprint phase and the probe phase's --favicon ask the same way, so
// their hashes agree. It takes the page's HTML rather than an Observation
// because that is all it reads — the probe's sweep holds no observation.
func FaviconRequest(origin *url.URL, page string) ProbeRequest {
	return ProbeRequest{Kind: KindFavicon, Method: http.MethodGet, Path: faviconPath(origin, page)}
}

// IconFrom hashes a favicon read's answer, nil when it is not an icon: no
// answer, an unreachable status, a body cut short (a hash over a prefix
// matches nothing), or a body that is not an image. baseURL is the origin the
// read went to.
func IconFrom(baseURL string, o *Observation) *FaviconInfo {
	if o == nil || o.Err != nil || !isReachable(o.Status) || o.Truncated {
		return nil
	}
	body := []byte(o.Body)
	if !LooksLikeIcon(body) {
		return nil
	}
	return HashFavicon(baseURL+o.Req.Path, body)
}

// faviconPath is the same-origin icon the page links, or /favicon.ico.
func faviconPath(origin *url.URL, page string) string {
	for _, tag := range iconLinkRE.FindAllString(page, 4) {
		if p := sameOriginPath(origin, attrValue(tag, "href")); p != "" {
			return p
		}
	}
	return "/favicon.ico"
}

// sourceMapPaths lists the maps worth asking for: the one a SourceMap header
// names, then <script src>.map for up to four same-origin scripts.
func sourceMapPaths(origin *url.URL, base *Observation) []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if p != "" && !seen[p] && len(out) < MaxSourceMaps {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, h := range []string{"SourceMap", "X-SourceMap"} {
		if v := base.Headers.Get(h); v != "" {
			add(sameOriginPath(origin, v))
		}
	}
	for _, src := range extractScriptSrcs(base.Body) {
		if p := sameOriginPath(origin, src); p != "" && strings.HasSuffix(strings.SplitN(p, "?", 2)[0], ".js") {
			add(strings.SplitN(p, "?", 2)[0] + ".map")
		}
	}
	return out
}

// sameOriginPath resolves ref against origin and returns its path (and query)
// when it stays on the origin, "" otherwise.
func sameOriginPath(origin *url.URL, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "data:") {
		return ""
	}
	u, err := origin.Parse(ref)
	if err != nil || !strings.EqualFold(u.Host, origin.Host) {
		return ""
	}
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	return p
}

// Analyze reads a pass's observations into a report. It sends nothing.
func Analyze(baseURL string, obs []Observation) *TechStackReport {
	report := &TechStackReport{BaseURL: baseURL, AllowedMethods: map[string][]string{}}
	if u, err := url.Parse(baseURL); err == nil {
		report.Hostname = u.Host
	}
	base := baseObservation(obs)
	notFound := learnNotFound(obs)
	var baseResp *probeResponse
	if base != nil {
		baseResp = asProbeResponse(base)
		report.SecurityHeaders = auditSecurityHeaders(base.Headers)
		report.BaseStatus = base.Status
		report.Server = base.Headers.Get("Server")
		report.PoweredBy = base.Headers.Get("X-Powered-By")
		report.AltSvc = base.Headers.Get("Alt-Svc")
		report.HTTPVersion = base.Proto
		report.BaseLocation = base.Headers.Get("Location")
		report.Title = HTMLTitle(base.Body)
	}

	for i := range obs {
		o := &obs[i]
		report.ProbeCount++
		if o.Err != nil {
			report.ProbeErrors++
			report.Errors = append(report.Errors, probeErrorOf(o))
			continue
		}
		r := asProbeResponse(o)
		// A path is reachable when it answers with a reachable status AND not
		// the way this origin answers a path that does not exist: on a host
		// that serves 200 (or 403) for everything, every well-known, stack and
		// sensitive path would otherwise "answer".
		reachable := isReachable(o.Status) && (o.Req.Kind == KindBase || !notFound.matches(o))
		if reachable && fingerprintedKinds[o.Req.Kind] {
			runFingerprintRules(report, r)
		}
		switch o.Req.Kind {
		case KindAPISpec:
			if reachable {
				if looksLikeAPISpec(o.Req.Meta, r) {
					report.APISpecs = append(report.APISpecs, APISpecDetection{
						URL: baseURL + o.Req.Path, Kind: o.Req.Meta, StatusCode: o.Status, Reachable: true})
				}
			}
		case KindGraphQL:
			if reachable {
				if strings.Contains(o.Body, `"__schema"`) {
					report.APISpecs = append(report.APISpecs, APISpecDetection{
						URL: baseURL + o.Req.Path, Kind: "graphql", StatusCode: o.Status, Reachable: true,
						Note: "introspection enabled"})
				}
			}
		case KindWellKnown:
			if reachable {
				snippet := ""
				if len(o.Body) > 0 && len(o.Body) < 4096 && looksTextual(o.Headers, o.Body) {
					snippet = truncate(o.Body, 200)
				}
				report.WellKnown = append(report.WellKnown, WellKnownEntry{Path: o.Req.Path, StatusCode: o.Status, Snippet: snippet})
			}
		case KindStack:
			if reachable {
				if idx, err := strconv.Atoi(o.Req.Meta); err == nil && idx >= 0 && idx < len(stackProbePaths) {
					sp := stackProbePaths[idx]
					report.Stacks = appendDetection(report.Stacks, StackDetection{
						Name: sp.Name, Category: sp.Category, Tag: sp.Tag, Confidence: ConfidenceHigh,
						Evidence: []string{sp.Reason + " (" + sp.Path + " " + httpStatus(o.Status) + ")"}})
				}
			}
		case KindSensitive:
			if reachable {
				report.SensitivePaths = append(report.SensitivePaths, SensitivePathEntry{
					Path: o.Req.Path, StatusCode: o.Status, Reason: o.Req.Meta})
			}
		case KindOptions:
			if allow := o.Headers.Get("Allow"); allow != "" {
				report.AllowedMethods[o.Req.Path] = splitMethods(allow)
			}
		case KindCORS:
			if ao := o.Headers.Get("Access-Control-Allow-Origin"); ao != "" {
				report.CORS = &CORSDetection{
					TestedOrigin:     corsTestOrigin,
					AllowOrigin:      ao,
					AllowCredentials: o.Headers.Get("Access-Control-Allow-Credentials"),
					AllowMethods:     o.Headers.Get("Access-Control-Allow-Methods"),
					Permissive:       ao == "*",
					Reflective:       ao == corsTestOrigin,
				}
			}
		case KindFavicon:
			if reachable {
				if icon := IconFrom(baseURL, o); icon != nil {
					report.Favicon = icon
					report.FaviconHash = icon.MD5
				}
			}
		case KindVHost:
			if baseResp != nil {
				if v, ok := vhostFinding(o.Req.Host, baseResp, r); ok {
					report.VHostFindings = append(report.VHostFindings, v)
				}
			}
		case KindSourceMap:
			if reachable && strings.Contains(o.Body, `"mappings"`) {
				report.SourceMaps = append(report.SourceMaps, baseURL+o.Req.Path)
			}
		}
	}

	if baseResp != nil {
		if signals := runJSFingerprint(baseResp); len(signals) > 0 {
			report.JSSignals = signals
		}
		if logins := runLoginFormScrape(baseResp, baseURL+"/"); len(logins) > 0 {
			report.LoginCandidates = logins
		}
	}
	if len(report.AllowedMethods) == 0 {
		report.AllowedMethods = nil
	}
	return report
}

// probeErrorOf names one unanswered probe for the report.
func probeErrorOf(o *Observation) ProbeError {
	kind := o.ErrKind
	if kind == "" {
		kind = ProbeErrNetwork
	}
	return ProbeError{Path: o.Req.Path, Method: o.Req.Method, Host: o.Req.Host, Probe: o.Req.Kind,
		Kind: kind, Error: o.Err.Error()}
}

// notFoundShapes is how an origin answers a missing path, learned from its
// answers to the random not-found probes. Only answers with a reachable status
// are kept: a real 404 already fails isReachable.
type notFoundShapes []notFoundShape

type notFoundShape struct {
	status int
	title  string
	length int
}

func learnNotFound(obs []Observation) notFoundShapes {
	var out notFoundShapes
	for i := range obs {
		o := &obs[i]
		if o.Req.Kind != KindNotFound || o.Err != nil || !isReachable(o.Status) {
			continue
		}
		out = append(out, notFoundShape{status: o.Status, title: HTMLTitle(o.Body), length: len(o.Body)})
	}
	return out
}

// matches reports whether o looks like the origin's not-found answer: the same
// status, and the same title when both pages have one, else a body length
// within 5% (32 bytes at least — templates echo the requested path).
func (n notFoundShapes) matches(o *Observation) bool {
	for _, s := range n {
		if o.Status != s.status {
			continue
		}
		if title := HTMLTitle(o.Body); s.title != "" && title != "" {
			// Two titled pages: the title decides.
			if title == s.title {
				return true
			}
			continue
		}
		d := len(o.Body) - s.length
		if d < 0 {
			d = -d
		}
		if d <= max(32, s.length/20) {
			return true
		}
	}
	return false
}

// fingerprintedKinds are the answers the header/body stack rules read. A
// sensitive path or a not-found probe says nothing about the stack.
var fingerprintedKinds = map[ProbeKind]bool{
	KindBase: true, KindAPISpec: true, KindGraphQL: true, KindWellKnown: true, KindStack: true,
}

// reachablePaths is "/" plus the well-known, API-definition and sensitive paths
// that answered as something other than the origin's not-found page, at most
// limit — the paths worth an OPTIONS. Cheaper than a full Analyze, which reads
// every body for stack rules this question does not need.
func reachablePaths(obs []Observation, limit int) []string {
	notFound := learnNotFound(obs)
	out := []string{"/"}
	seen := map[string]bool{"/": true}
	for i := range obs {
		o := &obs[i]
		switch o.Req.Kind {
		case KindWellKnown, KindAPISpec, KindSensitive:
		default:
			continue
		}
		if len(out) >= limit || o.Err != nil || !isReachable(o.Status) || notFound.matches(o) || seen[o.Req.Path] {
			continue
		}
		seen[o.Req.Path] = true
		out = append(out, o.Req.Path)
	}
	return out
}

func asProbeResponse(o *Observation) *probeResponse {
	return &probeResponse{URL: o.URL, Status: o.Status, Headers: o.Headers, Body: o.Body}
}

// vhostFinding compares a vhost variant's answer with the base response: a
// status flip, or a body length delta over 256 bytes (smaller deltas are the
// date and CSRF-token jitter every page has).
func vhostFinding(host string, base, got *probeResponse) (VHostFinding, bool) {
	delta := len(got.Body) - len(base.Body)
	if delta < 0 {
		delta = -delta
	}
	if got.Status == base.Status && delta < 256 {
		return VHostFinding{}, false
	}
	return VHostFinding{Host: host, StatusCode: got.Status, BodyDelta: delta, BaselineCode: base.Status,
		Reason: vhostReason(host, base.Status, got.Status, delta)}, true
}

var titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// HTMLTitle is a page's <title>, whitespace collapsed and capped at 200.
func HTMLTitle(body string) string {
	m := titleRE.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return truncate(strings.Join(strings.Fields(m[1]), " "), 200)
}
