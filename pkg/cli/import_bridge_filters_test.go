package cli

import (
	"strings"
	"testing"
)

func resetImportBridgeFlags(t *testing.T) {
	t.Helper()
	prev := struct {
		host, path, from, to, search string
		methods, exclude             []string
		status                       []int
		allHosts                     bool
		limit                        int
	}{
		importBridgeHost, importBridgePath, importBridgeFrom, importBridgeTo, importSearchFilter,
		importBridgeMethods, importBridgeExclude, importBridgeStatus, importBridgeAllHosts, importBridgeLimit,
	}
	importBridgeHost, importBridgePath, importBridgeFrom, importBridgeTo, importSearchFilter = "", "", "", "", ""
	importBridgeMethods, importBridgeExclude, importBridgeStatus = nil, nil, nil
	importBridgeAllHosts, importBridgeLimit = false, 0
	t.Cleanup(func() {
		importBridgeHost, importBridgePath, importBridgeFrom, importBridgeTo, importSearchFilter =
			prev.host, prev.path, prev.from, prev.to, prev.search
		importBridgeMethods, importBridgeExclude, importBridgeStatus = prev.methods, prev.exclude, prev.status
		importBridgeAllHosts, importBridgeLimit = prev.allHosts, prev.limit
	})
}

func TestImportBridgeRefusesUnfilteredPull(t *testing.T) {
	// The security item: an unfiltered pull copies every host the operator has
	// ever browsed — with those hosts' cookies and tokens — into this database.
	// Silence must not mean "all".
	resetImportBridgeFlags(t)
	_, err := buildImportBridgeQuery("proj")
	if err == nil {
		t.Fatal("unfiltered bridge import accepted")
	}
	// The refusal has to name the way out, or the operator answers it with
	// --all-hosts, which is the one thing it exists to discourage.
	if !strings.Contains(err.Error(), "--host") || !strings.Contains(err.Error(), "--all-hosts") {
		t.Errorf("refusal does not name the filters or the opt-in: %v", err)
	}
	if classifyExitCode(err) != ExitUsageError {
		t.Errorf("refusal exit code = %d, want %d", classifyExitCode(err), ExitUsageError)
	}
}

func TestImportBridgeAllHostsOptsIn(t *testing.T) {
	resetImportBridgeFlags(t)
	importBridgeAllHosts = true
	if _, err := buildImportBridgeQuery("proj"); err != nil {
		t.Errorf("--all-hosts still refused: %v", err)
	}
}

func TestImportBridgeAnyFilterSatisfiesTheGuard(t *testing.T) {
	for name, set := range map[string]func(){
		"host":    func() { importBridgeHost = "app.example.com" },
		"path":    func() { importBridgePath = "/api" },
		"method":  func() { importBridgeMethods = []string{"POST"} },
		"status":  func() { importBridgeStatus = []int{200} },
		"search":  func() { importSearchFilter = "token" },
		"exclude": func() { importBridgeExclude = []string{"png"} },
		"from":    func() { importBridgeFrom = "2d" },
		"limit":   func() { importBridgeLimit = 50 },
	} {
		t.Run(name, func(t *testing.T) {
			resetImportBridgeFlags(t)
			set()
			if !importBridgeFiltersActive() {
				t.Fatalf("%s not counted as a filter", name)
			}
			if _, err := buildImportBridgeQuery("proj"); err != nil {
				t.Errorf("%s did not satisfy the guard: %v", name, err)
			}
		})
	}
}

func TestImportBridgeQueryCarriesFilters(t *testing.T) {
	// Built through QueryFromFilters — the same translation traffic -B uses — so a
	// filter added to one path cannot silently go missing on the other.
	resetImportBridgeFlags(t)
	importBridgeHost = "app.example.com"
	importBridgeMethods = []string{"POST"}
	importBridgeStatus = []int{200, 302}
	importBridgeLimit = 25

	q, err := buildImportBridgeQuery("proj-1")
	if err != nil {
		t.Fatal(err)
	}
	if q.Host != "app.example.com" {
		t.Errorf("Host = %q", q.Host)
	}
	if len(q.Methods) != 1 || q.Methods[0] != "POST" {
		t.Errorf("Methods = %v", q.Methods)
	}
	if len(q.StatusCodes) != 2 {
		t.Errorf("StatusCodes = %v", q.StatusCodes)
	}
	if q.Limit != 25 {
		t.Errorf("Limit = %d", q.Limit)
	}
	if q.ProjectUUID != "proj-1" {
		t.Errorf("ProjectUUID = %q", q.ProjectUUID)
	}
	if q.Location != "proxy_history" {
		t.Errorf("Location = %q, want proxy_history", q.Location)
	}
}

func TestImportBridgeRejectsInvertedDateRange(t *testing.T) {
	resetImportBridgeFlags(t)
	importBridgeFrom = "2026-09-04"
	importBridgeTo = "2026-09-01"
	if _, err := buildImportBridgeQuery("proj"); err == nil {
		t.Error("inverted --from/--to accepted")
	}
}

func TestImportLimitForSeparatesListingFromImport(t *testing.T) {
	// One flag governed two unrelated things: -n is a display page size, and the
	// same value bounded the bridge query the import writes from. An untyped -n
	// must not truncate a write.
	if got := importLimitFor(100, false); got != 0 {
		t.Errorf("untyped -n: import limit = %d, want 0 (unlimited)", got)
	}
	if got := importLimitFor(100, true); got != 100 {
		t.Errorf("typed -n: import limit = %d, want 100 (honored)", got)
	}
}
