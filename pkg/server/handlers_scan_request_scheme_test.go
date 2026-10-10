package server

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/portsweep"
	"github.com/vigolium/vigolium/pkg/requestscheme"
)

// saturateNativeScans holds the admission semaphore full so a scan handler
// creates its row and then answers 503 without starting a background executor.
func saturateNativeScans(t *testing.T, h *Handlers) {
	t.Helper()
	for i := 0; i < cap(h.nativeScanSem); i++ {
		h.nativeScanSem <- struct{}{}
	}
	t.Cleanup(func() {
		for len(h.nativeScanSem) > 0 {
			<-h.nativeScanSem
		}
	})
}

func scanRequestRowTarget(t *testing.T, db *database.DB) string {
	t.Helper()
	var rows []*database.Scan
	require.NoError(t, db.NewSelect().Model(&rows).Where("name = ?", database.ScanNameScanRequest).Scan(context.Background()))
	require.Len(t, rows, 1)
	return rows[0].Target
}

// POST /api/scan-request settles a schemeless raw request the way the CLI
// does: a plain-http service on a non-standard port is probed and scanned over
// http://, not the https default that failed against it.
func TestHandleScanRequestProbesScheme(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)

	db, repo := newPinnedTestDB(t)
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	saturateNativeScans(t, h)
	app := fiber.New()
	app.Post("/api/scan-request", h.HandleScanRequest)

	raw := base64.StdEncoding.EncodeToString([]byte("GET /x HTTP/1.1\r\nHost: " + u.Host + "\r\n\r\n"))
	status, body := doReq(t, app, http.MethodPost, "/api/scan-request", `{"http_request_base64":"`+raw+`"}`, nil)
	require.Equal(t, http.StatusServiceUnavailable, status, string(body))
	assert.Equal(t, "http://"+u.Host+"/x", scanRequestRowTarget(t, db))
}

// The response names the target and its scheme_source; target_url pins the
// scheme and no_scheme_probe keeps the default, neither contacting the target.
func TestHandleScanRequestSchemeSource(t *testing.T) {
	orig := scanRequestSchemeResolver
	t.Cleanup(func() { scanRequestSchemeResolver = orig })
	probed := 0
	scanRequestSchemeResolver = func(context.Context, string, string, string, portsweep.SchemeOptions) portsweep.SchemeResolution {
		probed++
		return portsweep.SchemeResolution{Reachable: true, Scheme: "http"}
	}

	cases := []struct {
		name, extra, wantTarget, wantSource string
		wantProbes                          int
	}{
		{"probe", ``, "http://10.9.9.9:8080/x", requestscheme.SourceProbe, 1},
		{"target_url", `,"target_url":"https://10.9.9.9:8080"`, "https://10.9.9.9:8080/x", requestscheme.SourceExplicit, 0},
		{"no_scheme_probe", `,"no_scheme_probe":true`, "https://10.9.9.9:8080/x", requestscheme.SourceDefault, 0},
	}
	raw := base64.StdEncoding.EncodeToString([]byte("GET /x HTTP/1.1\r\nHost: 10.9.9.9:8080\r\n\r\n"))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probed = 0
			h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
			// No background executor: the handler is answered, the scan itself
			// is not under test.
			var started func()
			app := fiber.New()
			app.Post("/api/scan-request", func(c fiber.Ctx) error {
				return h.handleScanRequest(c, func(fn func()) bool { started = fn; return true })
			})
			status, body := doReq(t, app, http.MethodPost, "/api/scan-request", `{"http_request_base64":"`+raw+`"`+tc.extra+`}`, nil)
			require.Equal(t, http.StatusAccepted, status, string(body))
			assert.NotNil(t, started)
			assert.Contains(t, string(body), `"target":"`+tc.wantTarget+`"`)
			assert.Contains(t, string(body), `"scheme_source":"`+tc.wantSource+`"`)
			assert.Equal(t, tc.wantProbes, probed)
		})
	}
}

// A target the scope refuses is answered 422 before the probe: it is never
// contacted.
func TestHandleScanRequestRefusedTargetNotProbed(t *testing.T) {
	orig := scanRequestSchemeResolver
	t.Cleanup(func() { scanRequestSchemeResolver = orig })
	scanRequestSchemeResolver = func(context.Context, string, string, string, portsweep.SchemeOptions) portsweep.SchemeResolution {
		t.Fatal("a refused target must not be probed")
		return portsweep.SchemeResolution{}
	}
	settings := config.DefaultSettings()
	settings.Scope.Host = config.ScopeRule{Include: []string{"nomatch.example"}}
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, settings)
	app := fiber.New()
	app.Post("/api/scan-request", h.HandleScanRequest)

	raw := base64.StdEncoding.EncodeToString([]byte("GET /x HTTP/1.1\r\nHost: 10.9.9.9:8080\r\n\r\n"))
	status, body := doReq(t, app, http.MethodPost, "/api/scan-request", `{"http_request_base64":"`+raw+`"}`, nil)
	assert.Equal(t, http.StatusUnprocessableEntity, status, string(body))
}
