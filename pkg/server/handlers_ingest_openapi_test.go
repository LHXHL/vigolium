package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
)

// TestHandleIngestHTTP_OpenAPIWithURL is the regression for REST OpenAPI
// ingest with a `url`: BaseURL was never set, so the parser always failed with
// "base URL required". The url must become the base the operations target.
func TestHandleIngestHTTP_OpenAPIWithURL(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	h := newBasicHandlers(t, ServerConfig{DisableFetchResponse: true}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Post("/api/ingest-http", h.HandleIngestHTTP)

	spec := `{"openapi":"3.0.0","info":{"title":"t","version":"1"},` +
		`"paths":{"/pets":{"get":{"responses":{"200":{"description":"ok"}}}}}}`
	reqBody, _ := json.Marshal(map[string]string{
		"input_mode": "openapi",
		"url":        "https://api.example.test/v1",
		"content":    spec,
	})
	status, respBody := doReq(t, app, http.MethodPost, "/api/ingest-http", string(reqBody), nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", status, respBody)
	}
	var resp IngestHTTPResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, respBody)
	}
	if resp.Imported != 1 {
		t.Fatalf("imported = %d, want 1; body %s", resp.Imported, respBody)
	}

	var urls []string
	if err := db.NewSelect().Table("http_records").Column("url").Scan(context.Background(), &urls); err != nil {
		t.Fatalf("select urls: %v", err)
	}
	if len(urls) != 1 || !strings.HasPrefix(urls[0], "https://api.example.test/v1/pets") {
		t.Fatalf("persisted urls = %v, want one under https://api.example.test/v1/pets", urls)
	}
}
