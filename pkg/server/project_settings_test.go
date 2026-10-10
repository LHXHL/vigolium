package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

const (
	overlayProjectA = "0c0c0c0c-1111-2222-3333-444444444444"
	overlayProjectB = "0d0d0d0d-1111-2222-3333-444444444444"
)

func writeServerProjectOverlay(t *testing.T, projectUUID, body string) {
	t.Helper()
	path := config.ProjectConfigPath(projectUUID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	config.InvalidateProjectOverlay(projectUUID)
}

func postProjectJSON(t *testing.T, app *fiber.App, path, projectUUID string, body any) (int, []byte) {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	if projectUUID != "" {
		req.Header.Set("X-Project-UUID", projectUUID)
	}
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

// TestSettingsForProject: the request's project overlay is merged onto a
// private copy; the server's own settings and other projects are untouched.
func TestSettingsForProject(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	writeServerProjectOverlay(t, overlayProjectA, "scope:\n  host:\n    include: [\"a.example.com\"]\n")

	global := config.DefaultSettings()
	h := &Handlers{settings: global}

	got, err := h.settingsForProject(overlayProjectA)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Scope.Host.Include, []string{"a.example.com"}) {
		t.Fatalf("project A include = %q", got.Scope.Host.Include)
	}
	if !slices.Equal(global.Scope.Host.Include, config.DefaultSettings().Scope.Host.Include) {
		t.Fatalf("server settings mutated: %q", global.Scope.Host.Include)
	}
	other, err := h.settingsForProject(overlayProjectB)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(other.Scope.Host.Include, global.Scope.Host.Include) {
		t.Fatalf("project B (no overlay) include = %q, want global", other.Scope.Host.Include)
	}

	writeServerProjectOverlay(t, overlayProjectB, "scope: [\n")
	if _, err := h.settingsForProject(overlayProjectB); err == nil {
		t.Fatal("broken overlay accepted")
	}
}

// TestHandleRunScan_ProjectOverlay: POST /api/scans/run resolves under the
// X-Project-UUID's overlay — its strategy and scope reach the runner — and the
// request's own fields still outrank it.
func TestHandleRunScan_ProjectOverlay(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	writeServerProjectOverlay(t, overlayProjectA,
		"scope:\n  cli_origin_mode: strict\n  host:\n    include: [\"127.0.0.1\"]\nscanning_strategy:\n  default_strategy: lite\n")

	repo := newTestRepo(t)
	h := newBasicHandlers(t, ServerConfig{Concurrency: 5}, nil, repo.DB(), repo, config.DefaultSettings())
	app := fiber.New()
	app.Use(ProjectUUIDMiddleware(nil))
	app.Post("/api/scans/run", h.HandleRunScan)

	dryRun := func(t *testing.T, project string, body map[string]any) ScanResponse {
		t.Helper()
		body["targets"] = []string{"http://example.test/"}
		body["dry_run"] = true
		status, data := postProjectJSON(t, app, "/api/scans/run", project, body)
		if status != fiber.StatusOK {
			t.Fatalf("status = %d (%s)", status, data)
		}
		var resp ScanResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			t.Fatal(err)
		}
		return resp
	}

	t.Run("overlay strategy applies to its project only", func(t *testing.T) {
		if got := dryRun(t, overlayProjectA, map[string]any{}); got.Resolved == nil || got.Resolved.Strategy != "lite" {
			t.Fatalf("project A resolved = %+v, want the overlay's lite", got.Resolved)
		}
		if got := dryRun(t, "", map[string]any{}); got.Resolved == nil || got.Resolved.Strategy == "lite" {
			t.Fatalf("default project resolved = %+v, want the global strategy", got.Resolved)
		}
	})

	t.Run("request strategy outranks the overlay", func(t *testing.T) {
		if got := dryRun(t, overlayProjectA, map[string]any{"strategy": "deep"}); got.Resolved == nil || got.Resolved.Strategy != "deep" {
			t.Fatalf("resolved = %+v, want the request's deep", got.Resolved)
		}
	})

	t.Run("overlay scope reaches the runner", func(t *testing.T) {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "<html><body>ok</body></html>")
		}))
		defer target.Close()

		// The scan row records the origin-scope mode the runner resolved from
		// the settings it was handed: the overlay's strict, not the global
		// balanced default.
		status, data := postProjectJSON(t, app, "/api/scans/run", overlayProjectA, map[string]any{
			"targets": []string{target.URL + "/"},
			"only":    "discovery",
		})
		if status != fiber.StatusAccepted && status != fiber.StatusOK {
			t.Fatalf("status = %d (%s)", status, data)
		}
		var resp ScanResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			t.Fatal(err)
		}

		var scan *database.Scan
		deadline := time.Now().Add(60 * time.Second)
		for time.Now().Before(deadline) {
			s, err := repo.GetScanByUUID(context.Background(), resp.ScanUUID)
			if err == nil && s != nil && s.Status != "running" && s.Status != "queued" && s.Status != "pending" {
				scan = s
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if scan == nil {
			t.Fatal("scan did not finish")
		}
		if scan.ScopeOriginMode != "strict" {
			t.Fatalf("scan scope_origin_mode = %q, want the project overlay's strict", scan.ScopeOriginMode)
		}
		if h.settings.Scope.CLIOriginMode != config.DefaultCLIOriginMode {
			t.Fatalf("server settings mutated by the overlay: cli_origin_mode = %q", h.settings.Scope.CLIOriginMode)
		}
	})
}

// TestSingleRequestScanUsesProjectScope: the synchronous scope admission of
// /api/scan-url judges the X-Project-UUID's scope, not just the global one.
func TestSingleRequestScanUsesProjectScope(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	writeServerProjectOverlay(t, overlayProjectA, "scope:\n  host:\n    include: [\"nomatch.example\"]\n")

	db, repo := newPinnedTestDB(t)
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, config.DefaultSettings())
	app := fiber.New()
	app.Use(ProjectUUIDMiddleware(nil))
	app.Post("/api/scan-url", h.HandleScanURL)

	status, body := postProjectJSON(t, app, "/api/scan-url", overlayProjectA, map[string]any{"url": "http://a.example.test/p"})
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d (%s), want 422 from the project's scope", status, body)
	}
	if len(h.nativeScanSem) != 0 {
		t.Fatal("a background scan was started for a refused target")
	}
}
