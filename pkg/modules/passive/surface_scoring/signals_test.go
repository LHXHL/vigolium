package surface_scoring

import (
	"fmt"
	"math/bits"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// buildResponse assembles a raw HTTP response from a status line, extra headers
// and a body, so each test states exactly the wire bytes it means to test.
func buildResponse(t *testing.T, status int, headers map[string]string, body string) *httpmsg.HttpResponse {
	t.Helper()
	raw := fmt.Sprintf("HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	for k, v := range headers {
		raw += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	raw += fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(body), body)
	return httpmsg.NewHttpResponse([]byte(raw))
}

// buildItem pairs a bare GET for rawURL with the given response.
func buildItem(t *testing.T, rawURL string, status int, headers map[string]string, body string) *httpmsg.HttpRequestResponse {
	t.Helper()
	return buildItemWith(t, reqSpec{rawURL: rawURL}, status, headers, body)
}

// reqSpec describes the request half when a test needs more than a bare GET.
type reqSpec struct {
	method  string
	rawURL  string
	headers map[string]string
	body    string
}

// buildItemWith pairs an arbitrary request with an arbitrary response.
func buildItemWith(t *testing.T, rs reqSpec, status int, respHeaders map[string]string, respBody string) *httpmsg.HttpRequestResponse {
	t.Helper()
	u, err := url.Parse(rs.rawURL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", rs.rawURL, err)
	}
	secure := u.Scheme == "https"
	port := 80
	if secure {
		port = 443
	}
	if p := u.Port(); p != "" {
		if parsed, convErr := strconv.Atoi(p); convErr == nil {
			port = parsed
		}
	}
	method := rs.method
	if method == "" {
		method = "GET"
	}
	raw := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n", method, u.RequestURI(), u.Host)
	for k, v := range rs.headers {
		raw += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	if rs.body != "" {
		raw += fmt.Sprintf("Content-Length: %d\r\n", len(rs.body))
	}
	raw += "\r\n" + rs.body

	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure(u.Hostname(), port, secure),
		[]byte(raw),
	)
	return httpmsg.NewHttpRequestResponse(req, buildResponse(t, status, respHeaders, respBody))
}

// allSignals is every signal the module defines. TestScoreCeiling uses it to
// pin the contract that the signal count and pointsPerSignal stay in step.
var allSignals = []Signal{
	SignalHasInput, SignalStateChanging, SignalUpload,
	SignalTechStack, SignalLegacyStack, SignalAuthBearing,
	SignalRichHTML, SignalSPA, SignalJSON, SignalResponsive,
}

func TestSignalScore(t *testing.T) {
	tests := []struct {
		name    string
		signals Signal
		want    int
	}{
		{"none", 0, 0},
		{"one", SignalJSON, 10},
		{"two", SignalJSON | SignalResponsive, 20},
		{"five", SignalJSON | SignalResponsive | SignalTechStack | SignalHasInput | SignalStateChanging, 50},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.signals.Score(); got != tt.want {
				t.Errorf("Score() = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestScoreCeiling pins the scale contract: every signal set must total exactly
// 100. An eleventh signal added without revisiting pointsPerSignal would push
// the ceiling to 110, and a score that can exceed its documented maximum is one
// every consumer threshold (--min-surface, the REST filter) silently misreads.
func TestScoreCeiling(t *testing.T) {
	var all Signal
	for _, s := range allSignals {
		all |= s
	}
	if got := all.Score(); got != 100 {
		t.Errorf("all %d signals score %d, want exactly 100 — signal count and pointsPerSignal are out of step",
			len(allSignals), got)
	}
	// Guards against a duplicated bit in the const block, which would make two
	// signals the same bit and silently cap the score below 100. Counted with
	// math/bits rather than Score()'s own popcount so this is an independent
	// check and not the implementation agreeing with itself.
	if n := bits.OnesCount16(uint16(all)); n != len(allSignals) {
		t.Errorf("combined mask has %d distinct bits for %d signals — a bit is duplicated", n, len(allSignals))
	}
}

func TestIsRichHTML(t *testing.T) {
	nav := "<html><body>"
	for i := 0; i < richHTMLMinAnchors; i++ {
		nav += fmt.Sprintf(`<a href="/p%d">p</a>`, i)
	}
	nav += "</body></html>"

	tests := []struct {
		name string
		body string
		want bool
	}{
		{"empty", "", false},
		{"form input", `<html><body><form><input name="q"></form></body></html>`, true},
		{"textarea", "<html><body><textarea></textarea></body></html>", true},
		{"select", "<html><body><select><option>a</option></select></body></html>", true},
		{"enough anchors", nav, true},
		{"too few anchors", `<html><body><a href="/">home</a></body></html>`, false},
		// A non-document body reaching here (mislabeled Content-Type) must not be
		// judged on substring counts that mean nothing outside markup.
		{"json mislabeled as html", `{"a":"<a ","b":"<a ","c":"<a ","d":"<a ","e":"<a "}`, false},
		{"bare spa shell", `<html><body><div id="root"></div></body></html>`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRichHTML(tt.body); got != tt.want {
				t.Errorf("isRichHTML() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsStateChanging(t *testing.T) {
	tests := map[string]bool{
		"GET": false, "HEAD": false, "get": false,
		"POST": true, "PUT": true, "PATCH": true, "DELETE": true,
		"post": true, " put ": true,
	}
	for method, want := range tests {
		if got := isStateChanging(method); got != want {
			t.Errorf("isStateChanging(%q) = %v, want %v", method, got, want)
		}
	}
}

func TestHasLegacyHandlerExtension(t *testing.T) {
	tests := map[string]bool{
		"/index.php":         true,
		"/login.jsp":         true,
		"/submit.do":         true,
		"/Account/Edit.aspx": true,
		"/cgi-bin/test.cgi":  true,
		"/legacy.cfm":        true,
		"/x.phtml":           true,
		"/UPPER.PHP":         true,
		"/index.php/users/1": true, // PATH_INFO routing is the legacy shape
		"/api/v1/users":      false,
		"/":                  false,
		"/static/app.js":     false,
		"/data.json":         false,
		"/page.html":         false,
		"/report.pdf":        false,
		"/philosophy":        false, // must not match on a ".ph" prefix
		"/deleted":           false, // must not match ".do" inside a word
	}
	for path, want := range tests {
		if got := hasLegacyHandlerExtension(path); got != want {
			t.Errorf("hasLegacyHandlerExtension(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestIsResponsive(t *testing.T) {
	javaTrace := "at com.example.Svc.run(Svc.java:42)\nat com.example.Main.go(Main.java:7)\n"

	tests := []struct {
		name    string
		status  int
		headers map[string]string
		body    string
		want    bool
	}{
		{"200 with body", 200, nil, "hello", true},
		{"302 redirect", 302, map[string]string{"Location": "/next"}, "moved", true},
		{"200 empty body", 200, nil, "", false},
		{"404", 404, nil, "not found", false},
		{"500 without trace", 500, nil, "boom", false},
		// A verbose error is the application talking — the most interesting thing
		// a target can do — so it must not score as a dead end.
		{"500 with java stack trace", 500, nil, javaTrace, true},
		{"404 with java stack trace", 404, nil, javaTrace, true},
		// The edge is talking, not the application. A trace in a blocked body
		// (a challenge page quoting one) must not rescue it.
		{"cloudflare 403", 403, map[string]string{"Server": "cloudflare"}, "blocked", false},
		{"cloudflare 403 with trace", 403, map[string]string{"Server": "cloudflare"}, javaTrace, false},
		{"challenged 200", 200, map[string]string{"Cf-Mitigated": "challenge"}, "<html>jschl</html>", false},
		{"app 403", 403, nil, "denied", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := buildResponse(t, tt.status, tt.headers, tt.body)
			if got := isResponsive(resp); got != tt.want {
				t.Errorf("isResponsive() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsResponsiveNilResponse(t *testing.T) {
	if isResponsive(nil) {
		t.Error("isResponsive(nil) = true, want false")
	}
}

// TestHasClientInputExcludesPathPositions is a regression guard. An
// insertion-point analysis synthesizes path folder and filename positions from
// the path itself, so every URL with a segment has them — counting them made
// SignalHasInput fire on 100% of records, which adds a constant to every score
// and changes no ordering.
func TestHasClientInputExcludesPathPositions(t *testing.T) {
	tests := []struct {
		name string
		rs   reqSpec
		want bool
	}{
		{"bare GET on a path", reqSpec{rawURL: "https://example.com/users/profile"}, false},
		{"GET with query param", reqSpec{rawURL: "https://example.com/users?id=1"}, true},
		{
			"POST with form body",
			reqSpec{method: "POST", rawURL: "https://example.com/login",
				headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
				body:    "user=admin&pass=x"},
			true,
		},
		{
			"POST with JSON body",
			reqSpec{method: "POST", rawURL: "https://example.com/api",
				headers: map[string]string{"Content-Type": "application/json"},
				body:    `{"id":1}`},
			true,
		},
		// Headers and cookies are on every request; counting them would make the
		// signal universal in the same way path positions did.
		{
			"cookies only",
			reqSpec{rawURL: "https://example.com/dash",
				headers: map[string]string{"Cookie": "session=abc"}},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			item := buildItemWith(t, tt.rs, 200, map[string]string{"Content-Type": "text/html"}, "<html><body>x</body></html>")
			if got := hasClientInput(item.Request()); got != tt.want {
				t.Errorf("hasClientInput() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsAuthBearing(t *testing.T) {
	tests := []struct {
		name        string
		reqHeaders  map[string]string
		respHeaders map[string]string
		want        bool
	}{
		{"nothing", nil, nil, false},
		{"authorization header", map[string]string{"Authorization": "Bearer x"}, nil, true},
		{"request cookie", map[string]string{"Cookie": "session=abc"}, nil, true},
		{"response set-cookie", nil, map[string]string{"Set-Cookie": "session=abc; Path=/"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			item := buildItemWith(t, reqSpec{rawURL: "https://example.com/x", headers: tt.reqHeaders},
				200, tt.respHeaders, "body")
			if got := isAuthBearing(item.Request(), item.Response()); got != tt.want {
				t.Errorf("isAuthBearing() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsUpload(t *testing.T) {
	tests := []struct {
		name       string
		reqHeaders map[string]string
		body       string
		want       bool
	}{
		{"plain", nil, "<html><body>x</body></html>", false},
		{"multipart request", map[string]string{"Content-Type": "multipart/form-data; boundary=xy"}, "", true},
		{"file input in response", nil, `<html><body><input type="file" name="f"></body></html>`, true},
		{"unquoted file input", nil, "<html><body><input type=file></body></html>", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			item := buildItemWith(t, reqSpec{rawURL: "https://example.com/x", headers: tt.reqHeaders},
				200, map[string]string{"Content-Type": "text/html"}, tt.body)
			got := isMultipartRequest(item.Request()) || hasFileInput(item.Response().BodyLowerString())
			if got != tt.want {
				t.Errorf("upload signal = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestRecordSignalsNeverSetsTechStack locks in the two-phase split: the
// host-scoped signal must not be derivable per record, because under
// ParallelPassive that read races the fingerprint module that populates it.
func TestRecordSignalsNeverSetsTechStack(t *testing.T) {
	item := buildItem(t, "https://example.com/", 200,
		map[string]string{"Content-Type": "text/html"},
		`<html><body><form><input name="q"></form></body></html>`)

	got := recordSignals(item, "example.com", &modkit.ScanContext{})
	if got&SignalTechStack != 0 {
		t.Error("recordSignals set SignalTechStack; it must only be resolved in Flush")
	}
}

func TestRecordSignals(t *testing.T) {
	richHTML := `<html><body><form><input name="q"></form></body></html>`
	spaShell := `<html><body><div id="root"></div><script src="/static/js/main.abc.js"></script></body></html>`

	tests := []struct {
		name      string
		rs        reqSpec
		status    int
		headers   map[string]string
		body      string
		hostClass modkit.ContentClass
		want      Signal
	}{
		{
			name:    "static rich html page",
			rs:      reqSpec{rawURL: "https://example.com/about"},
			status:  200,
			headers: map[string]string{"Content-Type": "text/html; charset=utf-8"},
			body:    richHTML,
			want:    SignalRichHTML | SignalResponsive,
		},
		{
			name:    "json api read",
			rs:      reqSpec{rawURL: "https://example.com/api/items"},
			status:  200,
			headers: map[string]string{"Content-Type": "application/json"},
			body:    `{"items":[]}`,
			want:    SignalJSON | SignalResponsive,
		},
		{
			// An SPA shell is thin HTML: it earns the SPA signal but not the
			// rich-HTML one, and the two are independent rather than exclusive.
			name:    "spa shell is not rich",
			rs:      reqSpec{rawURL: "https://example.com/app"},
			status:  200,
			headers: map[string]string{"Content-Type": "text/html"},
			body:    spaShell,
			want:    SignalSPA | SignalResponsive,
		},
		{
			name: "authenticated json write with input",
			rs: reqSpec{method: "POST", rawURL: "https://example.com/api/users",
				headers: map[string]string{"Content-Type": "application/json", "Authorization": "Bearer x"},
				body:    `{"name":"a"}`},
			status:  200,
			headers: map[string]string{"Content-Type": "application/json"},
			body:    `{"ok":true}`,
			want:    SignalHasInput | SignalStateChanging | SignalAuthBearing | SignalJSON | SignalResponsive,
		},
		{
			name:    "legacy php handler with query",
			rs:      reqSpec{rawURL: "https://example.com/view.php?id=3"},
			status:  200,
			headers: map[string]string{"Content-Type": "text/html"},
			body:    richHTML,
			want:    SignalHasInput | SignalLegacyStack | SignalRichHTML | SignalResponsive,
		},
		{
			name: "multipart upload",
			rs: reqSpec{method: "POST", rawURL: "https://example.com/upload.jsp",
				headers: map[string]string{"Content-Type": "multipart/form-data; boundary=xy"},
				body:    "--xy\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n\r\nhi\r\n--xy--\r\n"},
			status:  200,
			headers: map[string]string{"Content-Type": "text/html"},
			body:    "<html><body>ok</body></html>",
			want:    SignalHasInput | SignalStateChanging | SignalUpload | SignalLegacyStack | SignalResponsive,
		},
		{
			// No Content-Type at all: the host's root class stands in, matching the
			// executor's content-class gate.
			name:      "host class fallback",
			rs:        reqSpec{rawURL: "https://example.com/x"},
			status:    200,
			headers:   nil,
			body:      `{"ok":true}`,
			hostClass: modkit.ContentClassJSON,
			want:      SignalJSON | SignalResponsive,
		},
		{
			// The record's own Content-Type wins over the host hint.
			name:      "record class beats host class",
			rs:        reqSpec{rawURL: "https://example.com/x"},
			status:    200,
			headers:   map[string]string{"Content-Type": "application/json"},
			body:      `{"ok":true}`,
			hostClass: modkit.ContentClassHTML,
			want:      SignalJSON | SignalResponsive,
		},
		{
			name:    "plain server error earns nothing",
			rs:      reqSpec{rawURL: "https://example.com/x"},
			status:  500,
			headers: map[string]string{"Content-Type": "text/html"},
			body:    "<html><body>error</body></html>",
			want:    0,
		},
		{
			// A protected JSON API still scores its content and auth signals.
			name:    "403 json keeps json and auth signals",
			rs:      reqSpec{rawURL: "https://example.com/api/x", headers: map[string]string{"Cookie": "s=1"}},
			status:  403,
			headers: map[string]string{"Content-Type": "application/json"},
			body:    `{"error":"forbidden"}`,
			want:    SignalAuthBearing | SignalJSON,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			item := buildItemWith(t, tt.rs, tt.status, tt.headers, tt.body)
			// The host class is now resolved inside recordSignals from the
			// registry, exactly as the executor supplies it in production.
			scanCtx := &modkit.ScanContext{ContentClass: modkit.NewContentClassRegistry()}
			if tt.hostClass != modkit.ContentClassUnknown {
				scanCtx.ContentClass.Set("example.com", tt.hostClass)
			}
			if got := recordSignals(item, "example.com", scanCtx); got != tt.want {
				t.Errorf("recordSignals() = %010b, want %010b", got, tt.want)
			}
		})
	}
}

func TestRecordSignalsNoResponse(t *testing.T) {
	if got := recordSignals(nil, "example.com", &modkit.ScanContext{}); got != 0 {
		t.Errorf("recordSignals(nil) = %v, want 0", got)
	}
}
