package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/types"
)

// testProfilesSettings returns default settings whose profiles_dir holds the
// intensity profiles (quick → lite, full → deep), so profile loading runs for
// real but hermetically.
func testProfilesSettings(t *testing.T) *config.Settings {
	t.Helper()
	dir := t.TempDir()
	for name, strategy := range map[string]string{"quick": "lite", "standard": "balanced", "full": "deep"} {
		body := "scanning_strategy:\n  default_strategy: " + strategy + "\n"
		if err := os.WriteFile(filepath.Join(dir, name+".yaml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	settings := config.DefaultSettings()
	settings.ScanningStrategy.ProfilesDir = dir
	return settings
}

// resolveScanOptions walks the same chain HandleRunScan walks for a given
// request, returning the final opts the runner would see.
func resolveScanOptions(t *testing.T, req RunScanRequest) *types.Options {
	t.Helper()

	if err := validateRunScanRequest(req); err != nil {
		t.Fatalf("validateRunScanRequest: %v", err)
	}
	opts, _, err := ResolveRunScanRequest(testProfilesSettings(t), 50, req, "test-project")
	if err != nil {
		t.Fatalf("ResolveRunScanRequest: %v", err)
	}
	return opts
}

// TestHandleRunScan_ResolvesPhases is the regression guard for the silent
// profile clobber: applying a profile must not zero the per-strategy phase
// tables, so intensity=deep should resolve to all phases enabled.
func TestHandleRunScan_ResolvesPhases(t *testing.T) {
	cases := []struct {
		name              string
		req               RunScanRequest
		wantProfile       string // expected opts.ScanningProfile
		wantExternal      bool
		wantDiscover      bool
		wantSpidering     bool
		wantKnownIssue    bool
		wantSkipDynamic   bool
		wantSkipIngestion bool
	}{
		{
			name:           "intensity=deep enables every phase",
			req:            RunScanRequest{Targets: []string{"http://example.test/"}, Intensity: "deep"},
			wantProfile:    "full",
			wantExternal:   true,
			wantDiscover:   true,
			wantSpidering:  true,
			wantKnownIssue: true,
		},
		{
			name:        "intensity=quick clamps to lite",
			req:         RunScanRequest{Targets: []string{"http://example.test/"}, Intensity: "quick"},
			wantProfile: "quick",
			// lite leaves only dynamic-assessment on
		},
		{
			name:              "only=dynamic-assessment overrides strategy",
			req:               RunScanRequest{Targets: []string{"http://example.test/"}, Only: "dynamic-assessment"},
			wantSkipIngestion: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := resolveScanOptions(t, tc.req)

			if tc.wantProfile != "" && opts.ScanningProfile != tc.wantProfile {
				t.Errorf("ScanningProfile = %q, want %q", opts.ScanningProfile, tc.wantProfile)
			}
			if opts.ExternalHarvestEnabled != tc.wantExternal {
				t.Errorf("ExternalHarvestEnabled = %v, want %v", opts.ExternalHarvestEnabled, tc.wantExternal)
			}
			if opts.DiscoverEnabled != tc.wantDiscover {
				t.Errorf("DiscoverEnabled = %v, want %v", opts.DiscoverEnabled, tc.wantDiscover)
			}
			if opts.SpideringEnabled != tc.wantSpidering {
				t.Errorf("SpideringEnabled = %v, want %v", opts.SpideringEnabled, tc.wantSpidering)
			}
			if opts.KnownIssueScanEnabled != tc.wantKnownIssue {
				t.Errorf("KnownIssueScanEnabled = %v, want %v", opts.KnownIssueScanEnabled, tc.wantKnownIssue)
			}
			if opts.SkipDynamicAssessment != tc.wantSkipDynamic {
				t.Errorf("SkipDynamicAssessment = %v, want %v", opts.SkipDynamicAssessment, tc.wantSkipDynamic)
			}
			if opts.SkipIngestion != tc.wantSkipIngestion {
				t.Errorf("SkipIngestion = %v, want %v", opts.SkipIngestion, tc.wantSkipIngestion)
			}
		})
	}
}

// TestResolveRunScanRequest_StrategyPace: REST used to skip the strategy's pace
// ceiling, so `strategy: lite` ran at full speed, and a typed rate_limit reached
// only known-issue-scan.
func TestResolveRunScanRequest_StrategyPace(t *testing.T) {
	target := []string{"http://example.test/"}
	cases := []struct {
		name                     string
		req                      RunScanRequest
		wantC, wantR, wantH      int
		wantExplicitConcurrency  bool
		wantPaceRateLimitWritten int
	}{
		{"lite with no pace fields narrows to the ceiling", RunScanRequest{Targets: target, Strategy: "lite"}, 10, 20, 10, false, 20},
		{"lite keeps an explicit concurrency", RunScanRequest{Targets: target, Strategy: "lite", Concurrency: 40}, 40, 20, 10, true, 20},
		{"explicit rate limit reaches the native limiter and the pace", RunScanRequest{Targets: target, Strategy: "balanced", RateLimit: 7}, 25, 7, 40, false, 7},
		{"balanced honours scanning_pace", RunScanRequest{Targets: target}, 25, 100, 40, false, 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			settings := testProfilesSettings(t)
			opts, _, err := ResolveRunScanRequest(settings, 50, tc.req, "p")
			if err != nil {
				t.Fatal(err)
			}
			if opts.Concurrency != tc.wantC || opts.RateLimit != tc.wantR || opts.MaxPerHost != tc.wantH {
				t.Errorf("pace = c%d r%d h%d, want c%d r%d h%d",
					opts.Concurrency, opts.RateLimit, opts.MaxPerHost, tc.wantC, tc.wantR, tc.wantH)
			}
			if opts.ConcurrencyExplicitlySet != tc.wantExplicitConcurrency {
				t.Errorf("ConcurrencyExplicitlySet = %v", opts.ConcurrencyExplicitlySet)
			}
			if settings.ScanningPace.RateLimit != tc.wantPaceRateLimitWritten {
				t.Errorf("scanning_pace.rate_limit = %d, want %d", settings.ScanningPace.RateLimit, tc.wantPaceRateLimitWritten)
			}
		})
	}
}

// TestResolveRequests_ClientErrors: every resolution failure is the caller's.
func TestResolveRequests_ClientErrors(t *testing.T) {
	if _, _, err := ResolveRunScanRequest(testProfilesSettings(t), 0,
		RunScanRequest{Targets: []string{"http://x.test/"}, ScanningProfile: "absent"}, "p"); err == nil {
		t.Error("run: a missing profile must be an error")
	}
	// The records route used to swallow this and scan without the profile.
	if _, _, err := resolveScanAllRecordsOptions(testProfilesSettings(t), 0,
		ScanAllRecordsRequest{ScanningProfile: "absent"}, "p"); err == nil {
		t.Error("records: a missing profile must be an error")
	}
	if _, _, err := resolveScanAllRecordsOptions(testProfilesSettings(t), 0,
		ScanAllRecordsRequest{Intensity: "ludicrous"}, "p"); err == nil {
		t.Error("records: an invalid intensity must be an error")
	}
}

// TestResolveScanAllRecordsOptions_StaysDynamicAssessment: the records route
// takes the strategy's pace but never its crawl phases.
func TestResolveScanAllRecordsOptions_StaysDynamicAssessment(t *testing.T) {
	settings := testProfilesSettings(t)
	opts, strategy, err := resolveScanAllRecordsOptions(settings, 0, ScanAllRecordsRequest{Intensity: "quick"}, "p")
	if err != nil {
		t.Fatal(err)
	}
	if strategy.Name != "lite" || opts.Concurrency != 10 || opts.RateLimit != 20 {
		t.Errorf("strategy=%q pace c%d r%d, want lite 10/20", strategy.Name, opts.Concurrency, opts.RateLimit)
	}
	if opts.DiscoverEnabled || opts.SpideringEnabled || opts.KnownIssueScanEnabled || opts.ExternalHarvestEnabled ||
		opts.SkipDynamicAssessment || !opts.SkipIngestion || opts.HeuristicsCheck != "none" {
		t.Errorf("records scan must be dynamic-assessment only: %+v", opts)
	}
}

// TestScanAllRecords_ProfileErrorIs400: end to end through the handler.
func TestScanAllRecords_ProfileErrorIs400(t *testing.T) {
	app, h := scanRecordsTestApp(t)
	seedRecords(t, h.repo, 1)
	resp, body := mustPostJSON(t, app, "/api/scan-all-records", map[string]any{"dry_run": true, "scanning_profile": "absent-profile"})
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("status = %d (%s), want 400", resp.StatusCode, body)
	}
	resp, body = mustPostJSON(t, app, "/api/scan-all-records", map[string]any{"dry_run": true})
	if resp.StatusCode != fiber.StatusOK || !strings.Contains(body, `"resolved":{`) {
		t.Fatalf("status = %d body = %s, want 200 with resolved pace", resp.StatusCode, body)
	}
}

// TestHandleRunScan_ResolvedInResponse: the accepted response says what will run.
func TestHandleRunScan_ResolvedInResponse(t *testing.T) {
	repo := newTestRepo(t)
	h := newBasicHandlers(t, ServerConfig{Concurrency: 5}, nil, repo.DB(), repo, config.DefaultSettings())
	app := fiber.New()
	app.Use(ProjectUUIDMiddleware(nil))
	app.Post("/api/scans/run", h.HandleRunScan)

	resp, body := mustPostJSON(t, app, "/api/scans/run", map[string]any{
		"targets": []string{"http://example.test/"}, "strategy": "lite", "dry_run": true,
	})
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("status = %d (%s)", resp.StatusCode, body)
	}
	var got ScanResponse
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	want := ScanResolved{Strategy: "lite", Concurrency: 10, RateLimit: 20, MaxPerHost: 10}
	if got.Resolved == nil || *got.Resolved != want {
		t.Fatalf("resolved = %+v, want %+v", got.Resolved, want)
	}
}

// TestRESTModuleSelectionCarriesPatterns: both scan routes hand the runner the
// raw modules / module_tags (as the CLI does for -m / --module-tag), so the
// JS/YAML extensions it loads are narrowed by the same patterns.
func TestRESTModuleSelectionCarriesPatterns(t *testing.T) {
	run, _, err := ResolveRunScanRequest(testProfilesSettings(t), 0, RunScanRequest{
		Targets: []string{"http://127.0.0.1:1"}, Modules: []string{"xss"}, ModuleTags: []string{"injection"},
	}, "p")
	if err != nil {
		t.Fatal(err)
	}
	records, _, err := resolveScanAllRecordsOptions(testProfilesSettings(t), 0, ScanAllRecordsRequest{
		Modules: []string{"xss"}, ModuleTags: []string{"injection"},
	}, "p")
	if err != nil {
		t.Fatal(err)
	}
	for name, opts := range map[string]*types.Options{"run": run, "records": records} {
		if !slices.Equal(opts.ModulePatterns, []string{"xss"}) || !slices.Equal(opts.ModuleTags, []string{"injection"}) {
			t.Errorf("%s: ModulePatterns=%v ModuleTags=%v, want [xss] [injection]", name, opts.ModulePatterns, opts.ModuleTags)
		}
	}

	// Unnarrowed: no patterns, so every loaded extension stays.
	all, _, err := ResolveRunScanRequest(testProfilesSettings(t), 0, RunScanRequest{Targets: []string{"http://127.0.0.1:1"}}, "p")
	if err != nil {
		t.Fatal(err)
	}
	if len(all.ModulePatterns) != 0 || len(all.ModuleTags) != 0 {
		t.Errorf("unnarrowed: ModulePatterns=%v ModuleTags=%v, want none", all.ModulePatterns, all.ModuleTags)
	}
}
