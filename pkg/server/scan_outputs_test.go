package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
)

// TestRenderScanReports covers the REST `output_formats` fix: a requested
// report format is rendered through the injected renderer to the per-format
// path the upload later looks for, scoped to the scan; jsonl (the runner's live
// stream) is left to the runner.
func TestRenderScanReports(t *testing.T) {
	db, repo := newPinnedTestDB(t)

	type call struct{ format, path, project, scan string }
	var calls []call
	cfg := ServerConfig{
		ReportFormats: []string{"html"},
		RenderReport: func(_ context.Context, _ *database.DB, format, outputPath, projectUUID, scanUUID string) error {
			calls = append(calls, call{format, outputPath, projectUUID, scanUUID})
			return os.WriteFile(outputPath, []byte("<html></html>"), 0o600)
		},
	}
	h := newBasicHandlers(t, cfg, &fakeQueue{}, db, repo, nil)

	base := filepath.Join(t.TempDir(), "output")
	outputs := scanOutputs{base: base, formats: []string{"jsonl", "html"}}
	h.renderScanReports("proj-1", "scan-1", outputs)

	if len(calls) != 1 {
		t.Fatalf("renderer calls = %d, want 1 (html only): %+v", len(calls), calls)
	}
	want := call{"html", base + ".html", "proj-1", "scan-1"}
	if calls[0] != want {
		t.Fatalf("renderer call = %+v, want %+v", calls[0], want)
	}
	if _, err := os.Stat(outputs.path("html")); err != nil {
		t.Fatalf("html report not written at the upload path: %v", err)
	}
}

// TestRenderScanReports_NoRenderer must not panic: a server with no renderer
// rejects report formats up front (resolveAPIOutputFormats), and a stray one
// reaching here is logged, not dereferenced.
func TestRenderScanReports_NoRenderer(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	h.renderScanReports("proj-1", "scan-1", scanOutputs{base: filepath.Join(t.TempDir(), "output"), formats: []string{"html"}})
}
