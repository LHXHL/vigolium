package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func writeOverlayFile(t *testing.T, projectUUID, body string) string {
	t.Helper()
	path := ProjectConfigPath(projectUUID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestApplyProjectOverlay(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	const proj = "11111111-aaaa-bbbb-cccc-000000000001"

	s := DefaultSettings()
	if err := ApplyProjectOverlay(s, ""); err != nil {
		t.Fatalf("empty project: %v", err)
	}
	if err := ApplyProjectOverlay(s, proj); err != nil {
		t.Fatalf("missing overlay: %v", err)
	}
	if !slices.Equal(s.Scope.Host.Include, DefaultSettings().Scope.Host.Include) {
		t.Fatalf("no overlay changed scope: %q", s.Scope.Host.Include)
	}

	path := writeOverlayFile(t, proj, "scope:\n  host:\n    include: [\"a.example.com\"]\n")
	s = DefaultSettings()
	if err := ApplyProjectOverlay(s, proj); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.Scope.Host.Include, []string{"a.example.com"}) {
		t.Fatalf("include = %q", s.Scope.Host.Include)
	}

	// A rewrite from another process (no in-process invalidation) is seen on
	// the next load: the cache revalidates against the file's mtime/size.
	if err := os.WriteFile(path, []byte("scope:\n  host:\n    include: [\"b.example.com\", \"c.example.com\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	s = DefaultSettings()
	if err := ApplyProjectOverlay(s, proj); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.Scope.Host.Include, []string{"b.example.com", "c.example.com"}) {
		t.Fatalf("stale overlay after rewrite: %q", s.Scope.Host.Include)
	}

	// An in-process write invalidates explicitly.
	if _, err := SetProjectOverlayValue(proj, "scope.host.include", func() *Settings {
		v := DefaultSettings()
		v.Scope.Host.Include = []string{"d.example.com"}
		return v
	}()); err != nil {
		t.Fatal(err)
	}
	s = DefaultSettings()
	if err := ApplyProjectOverlay(s, proj); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.Scope.Host.Include, []string{"d.example.com"}) {
		t.Fatalf("overlay after SetProjectOverlayValue: %q", s.Scope.Host.Include)
	}

	// Removing the file drops the overlay.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	s = DefaultSettings()
	if err := ApplyProjectOverlay(s, proj); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.Scope.Host.Include, DefaultSettings().Scope.Host.Include) {
		t.Fatalf("deleted overlay still applied: %q", s.Scope.Host.Include)
	}

	// A broken overlay is an error, not a silent no-op.
	writeOverlayFile(t, proj, "scope: [\n")
	if err := ApplyProjectOverlay(DefaultSettings(), proj); err == nil {
		t.Fatal("unparseable overlay applied without error")
	}
}

// TestCloneSettingsIsolatesOverlay: overlaying a project onto a clone must not
// write through shared maps, slices or pointers into the original — the server
// clones its live settings per request.
func TestCloneSettingsIsolatesOverlay(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	const proj = "11111111-aaaa-bbbb-cccc-000000000002"
	writeOverlayFile(t, proj, "scope:\n  host:\n    include: [\"a.example.com\"]\n"+
		"known_issue_scan:\n  severity_overrides:\n    noisy-template: low\n"+
		"scanning_strategy:\n  default_strategy: lite\n")

	orig := DefaultSettings()
	orig.KnownIssueScan.SeverityOverrides = map[string]string{"other-template": "info"}
	origStrategy := orig.ScanningStrategy.DefaultStrategy

	clone := CloneSettings(orig)
	if err := ApplyProjectOverlay(clone, proj); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(clone.Scope.Host.Include, []string{"a.example.com"}) || clone.ScanningStrategy.DefaultStrategy != "lite" {
		t.Fatalf("clone not overlaid: include=%q strategy=%q", clone.Scope.Host.Include, clone.ScanningStrategy.DefaultStrategy)
	}
	if _, ok := clone.KnownIssueScan.SeverityOverrides["noisy-template"]; !ok {
		t.Fatalf("clone map not overlaid: %v", clone.KnownIssueScan.SeverityOverrides)
	}
	if !slices.Equal(orig.Scope.Host.Include, DefaultSettings().Scope.Host.Include) {
		t.Fatalf("original scope mutated: %q", orig.Scope.Host.Include)
	}
	if _, leaked := orig.KnownIssueScan.SeverityOverrides["noisy-template"]; leaked {
		t.Fatalf("overlay leaked into the original's map: %v", orig.KnownIssueScan.SeverityOverrides)
	}
	if orig.ScanningStrategy.DefaultStrategy != origStrategy {
		t.Fatalf("original strategy mutated: %q", orig.ScanningStrategy.DefaultStrategy)
	}
	if CloneSettings(nil) != nil {
		t.Fatal("CloneSettings(nil) != nil")
	}
}
