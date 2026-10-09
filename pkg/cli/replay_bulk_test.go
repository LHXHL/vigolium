package cli

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
)

// resetReplayBulkFlags clears the package-level bulk-selection globals so each
// test starts from a known state (they persist across cobra runs in-process).
func resetReplayBulkFlags(t *testing.T) {
	t.Helper()
	reset := func() {
		replayAll = false
		replayBulkHost = ""
		replayBulkMethods = nil
		replayBulkStatus = nil
		replayBulkPath = ""
		replayBulkSource = ""
		replayBulkSearch = nil
		replayBulkHeaderSearch = ""
		replayBulkBody = ""
		replayBulkExclude = nil
		replayBulkExcludeHeader = ""
		replayBulkExcludeBody = ""
		replayBulkFrom = ""
		replayBulkTo = ""
		replayBulkSort = "created_at"
		replayBulkAsc = false
		replayBulkOffset = 0
		replayBulkLimit = 100
		replayConcurrency = 10
		replayWithBrowser = false
		replayNoRedirects = false
		replayOutputPath = ""
		replayInReplace = false
		replayBurpBridgeURL = ""
		globalStateless = false
		globalGlobDB = ""
		globalJSON = false
	}
	reset()
	globalProjectUUID = ""
	globalProjectName = ""
	t.Cleanup(reset)
}

func TestReplayBulkRequested(t *testing.T) {
	cases := []struct {
		name  string
		fuzzy string
		setup func()
		want  bool
	}{
		{"no flags", "", func() {}, false},
		{"--all", "", func() { replayAll = true }, true},
		{"positional fuzzy", "admin", func() {}, true},
		{"--host", "", func() { replayBulkHost = "example.com" }, true},
		{"--method", "", func() { replayBulkMethods = []string{"POST"} }, true},
		{"--status", "", func() { replayBulkStatus = []int{200} }, true},
		{"--path", "", func() { replayBulkPath = "/api" }, true},
		{"--source", "", func() { replayBulkSource = "ingest-proxy" }, true},
		{"--search", "", func() { replayBulkSearch = []string{"admin"} }, true},
		{"--header-search", "", func() { replayBulkHeaderSearch = "X-Api-Key" }, true},
		{"--body", "", func() { replayBulkBody = "token" }, true},
		{"--exclude-search", "", func() { replayBulkExclude = []string{"logout"} }, true},
		{"--exclude-header-search", "", func() { replayBulkExcludeHeader = "X-Internal" }, true},
		{"--exclude-body", "", func() { replayBulkExcludeBody = "healthcheck" }, true},
		{"--from", "", func() { replayBulkFrom = "2026-01-01" }, true},
		{"--to", "", func() { replayBulkTo = "2026-12-31" }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetReplayBulkFlags(t)
			tc.setup()
			if got := replayBulkRequested(tc.fuzzy); got != tc.want {
				t.Errorf("replayBulkRequested(%q) = %v, want %v", tc.fuzzy, got, tc.want)
			}
		})
	}
}

func TestBuildReplayBulkFilters_MapsFlags(t *testing.T) {
	resetReplayBulkFlags(t)
	replayBulkHost = "*.example.com"
	replayBulkMethods = []string{"GET", "POST"}
	replayBulkStatus = []int{200, 302}
	replayBulkPath = "/api/*"
	replayBulkSource = "ingest-proxy"
	replayBulkSearch = []string{"admin", "api"}
	replayBulkHeaderSearch = "X-Api-Key"
	replayBulkBody = "token"
	replayBulkExclude = []string{"logout"}
	replayBulkExcludeHeader = "X-Internal"
	replayBulkExcludeBody = "healthcheck"
	replayBulkSort = "status"
	replayBulkAsc = true
	replayBulkOffset = 20
	replayBulkLimit = 50
	globalStateless = true // project scoping off → empty ProjectUUID, no DB lookup

	f, err := buildReplayBulkFilters("dashboard")
	if err != nil {
		t.Fatalf("buildReplayBulkFilters: %v", err)
	}
	if f.HostPattern != "*.example.com" {
		t.Errorf("HostPattern = %q", f.HostPattern)
	}
	if len(f.Methods) != 2 || f.Methods[0] != "GET" {
		t.Errorf("Methods = %v", f.Methods)
	}
	if len(f.StatusCodes) != 2 || f.StatusCodes[1] != 302 {
		t.Errorf("StatusCodes = %v", f.StatusCodes)
	}
	if f.PathPattern != "/api/*" || f.Source != "ingest-proxy" {
		t.Errorf("PathPattern=%q Source=%q", f.PathPattern, f.Source)
	}
	if f.FuzzyTerm != "dashboard" {
		t.Errorf("FuzzyTerm = %q, want dashboard", f.FuzzyTerm)
	}
	// --search is repeatable and AND-combined, mirroring `vigolium traffic`.
	if got := f.EffectiveSearchTerms(); len(got) != 2 || got[0] != "admin" || got[1] != "api" {
		t.Errorf("EffectiveSearchTerms() = %v, want [admin api]", got)
	}
	if f.BodySearch != "token" {
		t.Errorf("BodySearch = %q", f.BodySearch)
	}
	// --header-search carries traffic's --header filter; -H/--header is the
	// unrelated override flag and must not reach the query.
	if f.HeaderSearch != "X-Api-Key" {
		t.Errorf("HeaderSearch = %q, want X-Api-Key", f.HeaderSearch)
	}
	if f.ExcludeHeaderSearch != "X-Internal" {
		t.Errorf("ExcludeHeaderSearch = %q, want X-Internal", f.ExcludeHeaderSearch)
	}
	if len(f.ExcludeTerms) != 1 || f.ExcludeTerms[0] != "logout" || f.ExcludeBodySearch != "healthcheck" {
		t.Errorf("ExcludeTerms=%v ExcludeBodySearch=%q", f.ExcludeTerms, f.ExcludeBodySearch)
	}
	if f.SortBy != "status" || !f.SortAsc {
		t.Errorf("SortBy=%q SortAsc=%v, want status/true", f.SortBy, f.SortAsc)
	}
	if f.Offset != 20 {
		t.Errorf("Offset = %d, want 20", f.Offset)
	}
	if f.ProjectUUID != "" {
		t.Errorf("ProjectUUID = %q, want empty under -S", f.ProjectUUID)
	}
	if f.Limit != 50 {
		t.Errorf("Limit = %d, want 50 (no --all)", f.Limit)
	}
}

func TestBuildReplayBulkFilters_ParsesDateRange(t *testing.T) {
	resetReplayBulkFlags(t)
	replayBulkFrom = "2026-01-01"
	replayBulkTo = "2026-06-30"
	globalStateless = true

	f, err := buildReplayBulkFilters("")
	if err != nil {
		t.Fatalf("buildReplayBulkFilters: %v", err)
	}
	if f.DateFrom == nil || f.DateFrom.Year() != 2026 || f.DateFrom.Month() != 1 {
		t.Errorf("DateFrom = %v, want 2026-01-01", f.DateFrom)
	}
	if f.DateTo == nil || f.DateTo.Month() != 6 {
		t.Errorf("DateTo = %v, want 2026-06-30", f.DateTo)
	}
}

func TestBuildReplayBulkFilters_RejectsBadDate(t *testing.T) {
	resetReplayBulkFlags(t)
	replayBulkFrom = "not-a-date"
	globalStateless = true

	if _, err := buildReplayBulkFilters(""); err == nil {
		t.Error("expected error for invalid --from date, got nil")
	}
}

func TestBuildReplayBulkFilters_AllLiftsLimit(t *testing.T) {
	resetReplayBulkFlags(t)
	replayAll = true
	replayBulkLimit = 100
	globalStateless = true

	f, err := buildReplayBulkFilters("")
	if err != nil {
		t.Fatalf("buildReplayBulkFilters: %v", err)
	}
	if f.Limit != 0 {
		t.Errorf("Limit = %d, want 0 (--all lifts the cap)", f.Limit)
	}
}

func TestSourceFromDBRecord(t *testing.T) {
	rec := &database.HTTPRecord{
		UUID:           "abc12345-0000",
		RawRequest:     []byte("GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		RawResponse:    []byte("HTTP/1.1 200 OK\r\n\r\nok"),
		StatusCode:     200,
		ResponseTimeMs: 42,
		Scheme:         "https",
		Hostname:       "example.com",
		Port:           443,
	}
	src := sourceFromDBRecord(rec)

	if string(src.BaselineRequest) != string(rec.RawRequest) {
		t.Error("BaselineRequest not carried through")
	}
	if src.BaselineStatus != 200 || src.BaselineResponseTime != 42 {
		t.Errorf("status/time = %d/%d", src.BaselineStatus, src.BaselineResponseTime)
	}
	if src.Scheme != "https" || src.Hostname != "example.com" || src.Port != 443 {
		t.Errorf("dest = %s://%s:%d", src.Scheme, src.Hostname, src.Port)
	}
	if src.RecordUUID != "abc12345-0000" {
		t.Errorf("RecordUUID = %q", src.RecordUUID)
	}
	if src.OriginLabel != "record abc12345-0000" {
		t.Errorf("OriginLabel = %q", src.OriginLabel)
	}
}

func TestParseReplayHeaderFlags(t *testing.T) {
	prev := replayHeaders
	t.Cleanup(func() { replayHeaders = prev })

	replayHeaders = []string{"X-Test: one", "Authorization: Bearer tok"}
	got, err := parseReplayHeaderFlags()
	if err != nil {
		t.Fatalf("parseReplayHeaderFlags: %v", err)
	}
	if got["X-Test"] != "one" || got["Authorization"] != "Bearer tok" {
		t.Errorf("overlay = %v", got)
	}
	if len(got) != 2 {
		t.Errorf("overlay size = %d, want 2: %v", len(got), got)
	}
}

func TestParseReplayHeaderFlags_MalformedErrors(t *testing.T) {
	prev := replayHeaders
	t.Cleanup(func() { replayHeaders = prev })

	// A malformed entry (no colon) fails fast — matching the single-source path.
	replayHeaders = []string{"X-Test: one", "malformed-no-colon"}
	if _, err := parseReplayHeaderFlags(); err == nil {
		t.Error("expected error for malformed --header, got nil")
	}
}
