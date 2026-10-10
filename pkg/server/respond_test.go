package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
)

// generatedAtRe blanks the clock fields so bodies can be compared as goldens.
var generatedAtRe = regexp.MustCompile(`"generated_at":"[^"]*","generated_at_ms":\d+`)

func normalizeBody(b []byte) string {
	return generatedAtRe.ReplaceAllString(strings.TrimSpace(string(b)), `"generated_at":"T","generated_at_ms":0`)
}

func doReq2(t *testing.T, app *fiber.App, method, path, body string, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 15 * time.Second})
	require.NoError(t, err, "%s %s", method, path)
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

var v2Header = map[string]string{apicontract.RESTAPIVersionHeader: "2"}

// TestRespondErrorGolden pins both error shapes.
func TestRespondErrorGolden(t *testing.T) {
	app := fiber.New()
	app.Use(apiVersionMiddleware(1))
	app.Get("/api/scans/:uuid", func(c fiber.Ctx) error {
		return respondError(c, fiber.StatusNotFound, fmt.Errorf("load: %w", ErrScanNotFound), "try scan ls")
	})
	app.Get("/api/plain", func(c fiber.Ctx) error {
		return respondErrorMsg(c, fiber.StatusConflict, "busy")
	})
	app.Get("/api/explicit", func(c fiber.Ctx) error {
		return respondErrorCode(c, fiber.StatusUnprocessableEntity, apicontract.CodeNoTargetsInScope, "nothing in scope")
	})

	cases := []struct {
		path    string
		headers map[string]string
		status  int
		want    string
	}{
		{"/api/scans/abc", nil, 404,
			`{"error":"load: scan not found","code":404,"error_code":"scan_not_found","details":"try scan ls"}`},
		{"/api/scans/abc", v2Header, 404,
			`{"schema_version":2,"command":"GET /api/scans/:uuid","route":"GET /api/scans/:uuid","ok":false,"error":{"code":"scan_not_found","message":"load: scan not found","status":404,"details":"try scan ls"},"generated_at":"T","generated_at_ms":0}`},
		{"/api/plain", nil, 409, `{"error":"busy","code":409,"error_code":"conflict"}`},
		{"/api/plain?api_version=2", nil, 409,
			`{"schema_version":2,"command":"GET /api/plain","route":"GET /api/plain","ok":false,"error":{"code":"conflict","message":"busy","status":409},"generated_at":"T","generated_at_ms":0}`},
		{"/api/explicit", nil, 422, `{"error":"nothing in scope","code":422,"error_code":"no_targets_in_scope"}`},
	}
	for _, tc := range cases {
		resp, body := doReq2(t, app, http.MethodGet, tc.path, "", tc.headers)
		assert.Equal(t, tc.status, resp.StatusCode, tc.path)
		assert.Equal(t, tc.want, normalizeBody(body), tc.path)
	}
}

// TestRespondListGolden pins the paginated list in both versions, and the
// bespoke list (v1 untouched, v2 enveloped with extras flattened).
func TestRespondListGolden(t *testing.T) {
	app := fiber.New()
	app.Use(apiVersionMiddleware(1))
	app.Get("/api/findings", func(c fiber.Ctx) error {
		return respondList(c, PaginatedResponse{
			ProjectUUID: "p1", Data: []string{"a", "b"}, Total: 5, Limit: 2, Offset: 0, HasMore: true,
		})
	})
	app.Get("/api/modules", func(c fiber.Ctx) error {
		var none []string
		return respondBespokeList(c, fiber.Map{"modules": none, "total": 0},
			PaginatedResponse{Data: none}, fiber.Map{"extensions_enabled": true, "items": "clash dropped"})
	})

	cases := []struct {
		path    string
		headers map[string]string
		want    string
	}{
		{"/api/findings", nil,
			`{"schema_version":1,"command":"finding","project_uuid":"p1","data":["a","b"],"total":5,"limit":2,"offset":0,"has_more":true}`},
		{"/api/findings", v2Header,
			`{"schema_version":2,"command":"finding","kind":"read","ok":true,"route":"GET /api/findings","project_uuid":"p1","project_scoped":true,"total":5,"offset":0,"limit":2,"has_more":true,"items":["a","b"],"generated_at":"T","generated_at_ms":0}`},
		{"/api/modules", nil, `{"modules":null,"total":0}`},
		{"/api/modules", map[string]string{"Accept": apicontract.RESTMediaTypeV2},
			`{"schema_version":2,"command":"module ls","kind":"read","ok":true,"route":"GET /api/modules","project_scoped":false,"total":0,"offset":0,"limit":0,"has_more":false,"items":[],"generated_at":"T","generated_at_ms":0,"extensions_enabled":true}`},
	}
	for _, tc := range cases {
		resp, body := doReq2(t, app, http.MethodGet, tc.path, "", tc.headers)
		assert.Equal(t, 200, resp.StatusCode, tc.path)
		assert.Equal(t, tc.want, normalizeBody(body), tc.path)
	}
}

// TestNegotiateAPIVersion is the negotiation table.
func TestNegotiateAPIVersion(t *testing.T) {
	cases := []struct {
		name    string
		def     int
		query   string
		headers map[string]string
		want    int
		wantErr bool
	}{
		{name: "default v1", def: 0, want: 1},
		{name: "configured default v2", def: 2, want: 2},
		{name: "unknown configured default is v1", def: 7, want: 1},
		{name: "query 2", def: 1, query: "api_version=2", want: 2},
		{name: "query v2", def: 1, query: "api_version=v2", want: 2},
		{name: "query 1 beats default 2", def: 2, query: "api_version=1", want: 1},
		{name: "header 2", def: 1, headers: map[string]string{apicontract.RESTAPIVersionHeader: "2"}, want: 2},
		{name: "accept v2", def: 1, headers: map[string]string{"Accept": "application/json, " + apicontract.RESTMediaTypeV2}, want: 2},
		{name: "accept v1 beats default 2", def: 2, headers: map[string]string{"Accept": apicontract.RESTMediaTypeV1}, want: 1},
		{name: "query beats header", def: 1, query: "api_version=1", headers: map[string]string{apicontract.RESTAPIVersionHeader: "2"}, want: 1},
		{name: "header beats accept", def: 1, headers: map[string]string{apicontract.RESTAPIVersionHeader: "1", "Accept": apicontract.RESTMediaTypeV2}, want: 1},
		{name: "unknown query", def: 1, query: "api_version=3", wantErr: true},
		{name: "unknown header", def: 1, headers: map[string]string{apicontract.RESTAPIVersionHeader: "two"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := fiber.New()
			app.Use(apiVersionMiddleware(tc.def))
			app.Get("/api/x", func(c fiber.Ctx) error { return c.SendString(fmt.Sprint(requestAPIVersion(c))) })
			path := "/api/x"
			if tc.query != "" {
				path += "?" + tc.query
			}
			resp, body := doReq2(t, app, http.MethodGet, path, "", tc.headers)
			if tc.wantErr {
				assert.Equal(t, 400, resp.StatusCode)
				assert.Contains(t, string(body), string(apicontract.CodeUnsupportedAPIVersion))
				return
			}
			assert.Equal(t, 200, resp.StatusCode)
			assert.Equal(t, fmt.Sprint(tc.want), string(body))
			assert.Equal(t, fmt.Sprint(tc.want), resp.Header.Get(apicontract.RESTAPIVersionHeader))
			assert.Contains(t, resp.Header.Get("Vary"), apicontract.RESTAPIVersionHeader)
		})
	}
}

// TestNoInlineErrorResponse keeps every error body on the helpers: a literal
// ErrorResponse{} written straight to the client skips error_code and the v2
// shape.
func TestNoInlineErrorResponse(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	re := regexp.MustCompile(`JSON\(&?ErrorResponse\{`)
	var hits []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "respond.go" {
			continue
		}
		raw, err := os.ReadFile(f)
		require.NoError(t, err)
		for i, line := range strings.Split(string(raw), "\n") {
			if re.MatchString(line) {
				hits = append(hits, fmt.Sprintf("%s:%d", f, i+1))
			}
		}
	}
	assert.Empty(t, hits, "write errors with respondError/respondErrorMsg/respondErrorCode (respond.go), not JSON(ErrorResponse{...})")
}

// TestErrorCodeForSentinels: every sentinel maps to a code in the closed set,
// and a wrapped sentinel still classifies.
func TestErrorCodeForSentinels(t *testing.T) {
	for _, s := range errorCodeSentinels {
		assert.True(t, s.code.Valid(), "%v → %q is not in apicontract", s.err, s.code)
		assert.Equal(t, s.code, errorCodeFor(fmt.Errorf("ctx: %w", s.err), 500), "%v", s.err)
	}
	assert.Equal(t, apicontract.CodeDatabaseLocked, errorCodeFor(fmt.Errorf("q: %w", database.ErrDatabaseLocked), 500))
	assert.Equal(t, apicontract.CodeNotFound, errorCodeFor(errors.New("nope"), 404))
	for status := 400; status < 600; status++ {
		assert.True(t, statusErrorCode(status).Valid(), "status %d", status)
	}
}

// routeWalkApp is the full production route table on a seeded DB, with the
// production error handler.
func routeWalkApp(t *testing.T) (*fiber.App, map[string]string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	db, repo := newPinnedTestDB(t)
	ctx := context.Background()

	scanUUID := "11111111-1111-1111-1111-111111111111"
	require.NoError(t, repo.CreateScan(ctx, &database.Scan{UUID: scanUUID, ProjectUUID: database.DefaultProjectUUID, Status: "completed"}))
	sessionDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(sessionDir, "plan.md"), []byte("# plan"), 0o600))
	agentUUID := "22222222-2222-2222-2222-222222222222"
	require.NoError(t, repo.CreateAgenticScan(ctx, &database.AgenticScan{
		UUID: agentUUID, ProjectUUID: database.DefaultProjectUUID, Mode: "query", AgentName: "test",
		Status: "completed", SessionDir: sessionDir,
	}))

	cfg := ServerConfig{NoAuth: true, NoAgent: true}
	h := NewHandlers(&fakeQueue{}, db, repo, nil, cfg, config.DefaultSettings(), nil, nil)
	t.Cleanup(func() { h.Close() })
	app := fiber.New(fiber.Config{ErrorHandler: apiErrorHandler})
	registerRoutes(app, h, cfg)
	params := map[string]string{
		":uuid":  scanUUID,
		":id":    agentUUID,
		":table": "findings",
	}
	return app, params
}

func fillParams(path string, params map[string]string) string {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		if v, ok := params[s]; ok {
			segs[i] = v
		}
	}
	return strings.Join(segs, "/")
}

// TestRouteWalkV2Lists: every registered GET route is classified as a list
// or an object, and every list route answers the v2 envelope.
func TestRouteWalkV2Lists(t *testing.T) {
	app, params := routeWalkApp(t)
	seen := map[string]bool{}
	for _, r := range app.GetRoutes(true) {
		if r.Method != http.MethodGet {
			continue
		}
		key := r.Method + " " + r.Path
		seen[key] = true
		_, isList := restRouteContracts[key]
		if !isList && !restObjectRoutes[key] {
			t.Errorf("GET route %s is not classified: add it to restRouteContracts (list) or restObjectRoutes (respond.go)", key)
			continue
		}
		if !isList {
			continue
		}
		path := fillParams(r.Path, params)
		resp, body := doReq2(t, app, http.MethodGet, path, "", v2Header)
		if !assert.Equal(t, 200, resp.StatusCode, "%s: %s", key, body) {
			continue
		}
		assert.Equal(t, "2", resp.Header.Get(apicontract.RESTAPIVersionHeader), key)
		var env map[string]any
		require.NoError(t, json.Unmarshal(body, &env), key)
		assert.EqualValues(t, 2, env["schema_version"], key)
		assert.Equal(t, true, env["ok"], key)
		assert.Equal(t, key, env["route"], key)
		assert.NotEmpty(t, env["command"], key)
		_, isArr := env["items"].([]any)
		assert.True(t, isArr, "%s: items must be an array, got %T", key, env["items"])
		assert.Contains(t, env, "total", key)
		assert.Contains(t, env, "has_more", key)
		assert.NotContains(t, env, "data", key)

		// v1 of the paginated routes carries the additive fields.
		resp, body = doReq2(t, app, http.MethodGet, path, "", nil)
		require.Equal(t, 200, resp.StatusCode, key)
		assert.Equal(t, "1", resp.Header.Get(apicontract.RESTAPIVersionHeader), key)
		var v1 any
		require.NoError(t, json.Unmarshal(body, &v1), key)
		if m, ok := v1.(map[string]any); ok {
			if _, paginated := m["data"]; paginated {
				assert.EqualValues(t, 1, m["schema_version"], key)
				assert.NotEmpty(t, m["command"], key)
			}
		}
	}
	for key := range restRouteContracts {
		assert.True(t, seen[key], "restRouteContracts lists %s, which is not registered", key)
	}
	for key := range restObjectRoutes {
		assert.True(t, seen[key], "restObjectRoutes lists %s, which is not registered", key)
	}
}

// routeWalkSkipErrors are routes the error walk does not hit.
var routeWalkSkipErrors = map[string]string{
	"GET /favicon.ico": "static file",
}

// TestEveryErrorCarriesCode walks every registered route with requests built
// to fail (unknown ids, malformed bodies) and asserts that every non-2xx JSON
// body carries the string code: error_code in v1, error.code in v2.
func TestEveryErrorCarriesCode(t *testing.T) {
	app, _ := routeWalkApp(t)
	bogus := map[string]string{
		":uuid":      "00000000-0000-0000-0000-00000000dead",
		":id":        "999999",
		":table":     "no_such_table",
		":name":      "no-such-extension",
		":key":       "no-such-key",
		":scan_uuid": "00000000-0000-0000-0000-00000000dead",
		"*":          "nope.txt",
	}
	var routes []string
	for _, r := range app.GetRoutes(true) {
		if r.Method == http.MethodHead || r.Method == http.MethodOptions {
			continue
		}
		routes = append(routes, r.Method+" "+r.Path)
	}
	sort.Strings(routes)
	checked := 0
	for _, key := range routes {
		if _, skip := routeWalkSkipErrors[key]; skip {
			continue
		}
		method, path, _ := strings.Cut(key, " ")
		path = fillParams(path, bogus)
		body := ""
		if method != http.MethodGet && method != http.MethodDelete {
			body = `{"malformed":`
		}
		for _, version := range []int{1, 2} {
			headers := map[string]string{}
			if version == 2 {
				headers = v2Header
			}
			resp, raw := doReq2(t, app, method, path, body, headers)
			if resp.StatusCode < 400 {
				t.Logf("%s (v%d): %d", key, version, resp.StatusCode)
				continue
			}
			if !strings.Contains(resp.Header.Get("Content-Type"), "json") {
				t.Errorf("%s (v%d): %d with Content-Type %q, want a JSON error", key, version, resp.StatusCode, resp.Header.Get("Content-Type"))
				continue
			}
			var m map[string]any
			if !assert.NoError(t, json.Unmarshal(raw, &m), "%s: %s", key, raw) {
				continue
			}
			checked++
			if version == 1 {
				code, _ := m["error_code"].(string)
				assert.True(t, apicontract.ErrorCode(code).Valid(), "%s (v1): error_code %q in %s", key, code, raw)
				assert.EqualValues(t, resp.StatusCode, m["code"], "%s (v1): code must be the HTTP status", key)
				continue
			}
			e, _ := m["error"].(map[string]any)
			code, _ := e["code"].(string)
			assert.True(t, apicontract.ErrorCode(code).Valid(), "%s (v2): error.code %q in %s", key, code, raw)
			assert.EqualValues(t, resp.StatusCode, e["status"], "%s (v2)", key)
			assert.Equal(t, false, m["ok"], key)
		}
	}
	assert.Greater(t, checked, 50, "the walk produced too few error responses to mean anything")

	// The router's own errors too.
	resp, raw := doReq2(t, app, http.MethodGet, "/api/no-such-route", "", nil)
	assert.Equal(t, 404, resp.StatusCode)
	assert.Contains(t, string(raw), `"error_code":"not_found"`)
}

// TestSwaggerErrorCodeEnum: the spec's error-code enums are the closed set,
// so a code added to pkg/apicontract cannot ship undocumented.
func TestSwaggerErrorCodeEnum(t *testing.T) {
	doc := loadSwaggerDoc(t)
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	want := make([]string, 0)
	for _, c := range apicontract.ErrorCodes() {
		want = append(want, string(c))
	}
	for _, at := range [][2]string{{"ErrorResponse", "error_code"}, {"ErrorV2", "code"}} {
		props := schemas[at[0]].(map[string]any)["properties"].(map[string]any)
		raw, _ := props[at[1]].(map[string]any)["enum"].([]any)
		got := make([]string, 0, len(raw))
		for _, v := range raw {
			got = append(got, v.(string))
		}
		sort.Strings(got)
		assert.Equal(t, want, got, "%s.%s enum drifted from apicontract.ErrorCodes() (edit docs/development/api-swagger.json, then `make swagger`)", at[0], at[1])
	}
}
