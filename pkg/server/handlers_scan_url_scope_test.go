package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
)

// A single-request REST scan whose target the configured scope refuses is a
// synchronous 422 no_targets_in_scope: no scan row, no background executor,
// nothing sent. It used to be a 202 for a scan that then did nothing.
func TestSingleRequestScanRejectedByScopeIs422(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	settings := config.DefaultSettings()
	settings.Scope.Host = config.ScopeRule{Include: []string{"nomatch.example"}}
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, settings)

	app := fiber.New()
	app.Post("/api/scan-url", h.HandleScanURL)
	app.Post("/api/scan-request", h.HandleScanRequest)

	rawReq := base64.StdEncoding.EncodeToString([]byte("GET /x HTTP/1.1\r\nHost: b.example.test\r\n\r\n"))
	cases := []struct{ name, path, body string }{
		{"scan-url", "/api/scan-url", `{"url":"http://a.example.test/p"}`},
		{"scan-request", "/api/scan-request", `{"http_request_base64":"` + rawReq + `","target_url":"http://b.example.test/x"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body := doReq(t, app, http.MethodPost, tc.path, tc.body, nil)
			require.Equal(t, http.StatusUnprocessableEntity, status, string(body))
			var resp ErrorResponse
			require.NoError(t, json.Unmarshal(body, &resp))
			assert.Equal(t, http.StatusUnprocessableEntity, resp.Code)
			assert.Equal(t, string(apicontract.CodeNoTargetsInScope), resp.Details)
			assert.Contains(t, resp.Error, config.ScopeRuleHostInclude, "the message names the rule")

			var rows []*database.Scan
			require.NoError(t, db.NewSelect().Model(&rows).Where("name = ?", tc.name).Scan(context.Background()))
			assert.Empty(t, rows, "a refused target creates no scan row")
		})
	}
	assert.Zero(t, len(h.nativeScanSem), "no background scan was started")
}
