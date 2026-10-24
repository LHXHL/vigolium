package nextjs_middleware_bypass

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// catchAllShell is the generic 200 app shell a wildcard Next.js host serves for
// every unmatched route — shared by the two catch-all false-positive tests.
const catchAllShell = `<html><body>Welcome to our platform — explore products and pricing` +
	`<script src="/_next/static/chunks/main.js"></script></body></html>`

// seedNext403 builds a request to rawURL with a synthetic 403 baseline whose body
// carries a Next.js marker (/_next/), so the module's framework gate and its
// 401/403 entry gate both fire.
func seedNext403(t *testing.T, rawURL string) *httpmsg.HttpRequestResponse {
	t.Helper()
	base := modtest.Request(t, rawURL)
	body := `<html><body>Forbidden<script src="/_next/static/chunks/main.js"></script></body></html>`
	rawResp := fmt.Sprintf("HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(base.Request(), resp)
}

// TestScanPerRequest_DetectsPathBypass drives the real scan method against a
// Next.js host that genuinely enforces middleware on the clean path (/admin →
// 403) while a path rewrite (//admin, /en/admin, …) reaches distinct protected
// content with 200, and a random path is a real 404. The rewrite body differs
// from the 404 catch-all control, so it is reported as a genuine bypass.
func TestScanPerRequest_DetectsPathBypass(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/admin":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<html><body>Forbidden<script src="/_next/x.js"></script></body></html>`))
		case strings.Contains(r.URL.Path, "admin"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><body>SECRET ADMIN DASHBOARD with privileged controls` +
				`<script src="/_next/x.js"></script></body></html>`))
		default:
			// Random catch-all probe is a genuine 404.
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`<html><body>not here<script src="/_next/x.js"></script></body></html>`))
		}
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(seedNext403(t, srv.URL+"/admin"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when a path rewrite reaches distinct protected content")
	assert.Equal(t, ModuleID, res[0].ModuleID)
}

// TestScanPerRequest_NoFalsePositive_CatchAllShell reproduces the path-phase FP
// class: a Next.js app serves one generic 200 app shell (a [...slug] catch-all /
// marketing home) for every unmatched route. The clean /admin stays 403 (so the
// confirm rounds' still-denied check passes) and the header phase finds nothing,
// but every path rewrite returns the generic shell — identical to the host's
// response to a random nonexistent path. Only the catch-all control catches that
// the rewrite reached the shell, not the protected resource.
func TestScanPerRequest_NoFalsePositive_CatchAllShell(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The clean protected path stays forbidden (the header never helps);
		// everything else — rewrites and the random catch-all probe — returns the
		// same generic 200 shell.
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<html><body>Forbidden<script src="/_next/x.js"></script></body></html>`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(catchAllShell))
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(seedNext403(t, srv.URL+"/admin"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a path rewrite that lands on the generic catch-all shell must not be reported as a middleware bypass")
}

// TestScanPerRequest_NoFalsePositive_CatchAllShell_ThrottledProbe reproduces the
// WAF-flake variant of the catch-all FP — the exact class that produced the
// off-by-slash false positive on a WAF/CDN-fronted host. The app is the same
// wildcard catch-all as above (every unmatched route → one 200 shell), but the
// primary single-probe catch-all control (/<canary>-vigolium404) is throttled to a
// 503. The OLD guard fails OPEN on that non-200 control and reports the shell as a
// Critical bypass; the hardened guard also samples the site root "/" and a random
// web-root directory independently, so the throttled probe cannot hide the shell.
func TestScanPerRequest_NoFalsePositive_CatchAllShell_ThrottledProbe(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/admin":
			// Clean protected path stays forbidden.
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<html><body>Forbidden<script src="/_next/x.js"></script></body></html>`))
		case strings.Contains(r.URL.Path, "-vigolium404"):
			// The lone original-template catch-all control is WAF-throttled to a
			// non-200, disabling the old single-probe guard (fail-open).
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("throttled"))
		default:
			// Every other route — the path rewrites, the site root "/", and the
			// random web-root directory the hardened guard samples — is the shell.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(catchAllShell))
		}
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(seedNext403(t, srv.URL+"/admin"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a wildcard-shell bypass must not be reported even when the single-probe catch-all control is throttled")
}
