package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestKitParamMine_JSON mines a local endpoint whose hidden parameter is only
// in a -w wordlist and checks the -j envelope: the parameter as an item, the
// run's counters at the top level.
func TestKitParamMine_JSON(t *testing.T) {
	page := strings.Repeat("<div>plain listing row</div>\n", 30)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := page
		if r.URL.Query().Has("zzhiddenknob") {
			body += strings.Repeat("<pre>verbose diagnostics enabled</pre>\n", 20)
		}
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()

	wl := filepath.Join(t.TempDir(), "names.txt")
	if err := os.WriteFile(wl, []byte("# custom\nalpha\nzzhiddenknob\nbeta\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	saved := struct {
		target, method, data, loc string
		wordlists                 []string
		noBuiltin, json           bool
		maxReq, rate              int
	}{kitParamMineTarget, kitParamMineMethod, kitParamMineData, kitParamMineLocation, kitParamMineWordlists,
		kitParamMineNoBuiltin, globalJSON, kitParamMineMaxRequests, kitParamMineRateLimit}
	t.Cleanup(func() {
		kitParamMineTarget, kitParamMineMethod, kitParamMineData, kitParamMineLocation = saved.target, saved.method, saved.data, saved.loc
		kitParamMineWordlists, kitParamMineNoBuiltin, globalJSON = saved.wordlists, saved.noBuiltin, saved.json
		kitParamMineMaxRequests, kitParamMineRateLimit = saved.maxReq, saved.rate
		jsonResultEmitted = false
	})
	kitParamMineTarget = srv.URL + "/list?page=2"
	kitParamMineMethod, kitParamMineData, kitParamMineLocation = "GET", "", "auto"
	kitParamMineWordlists, kitParamMineNoBuiltin = []string{wl}, true
	kitParamMineMaxRequests, kitParamMineRateLimit = 60, 0
	globalJSON = true

	var runErr error
	out := captureStdout(t, func() { runErr = runKitParamMine(kitParamMineCmd, nil) })
	if runErr != nil {
		t.Fatalf("runKitParamMine: %v", runErr)
	}
	var doc struct {
		Kind     string             `json:"kind"`
		Items    []kitParamMineItem `json:"items"`
		Location string             `json:"location"`
		Tested   int                `json:"names_tested"`
		Requests int                `json:"requests"`
		Aborted  string             `json:"aborted"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if doc.Kind != "read" || doc.Location != "query" || doc.Tested != 3 || doc.Aborted != "" {
		t.Errorf("envelope = %+v", doc)
	}
	if len(doc.Items) != 1 || doc.Items[0].Name != "zzhiddenknob" || doc.Items[0].Signal != "length" {
		t.Fatalf("items = %+v, want zzhiddenknob by length", doc.Items)
	}
	if !strings.Contains(doc.Items[0].URL, "page=2") || doc.Items[0].Status != 200 {
		t.Errorf("item = %+v", doc.Items[0])
	}
}

func TestKitParamMine_UsageErrors(t *testing.T) {
	saved := kitParamMineTarget
	t.Cleanup(func() { kitParamMineTarget = saved })
	kitParamMineTarget = ""
	if err := runKitParamMine(kitParamMineCmd, nil); err == nil || !strings.Contains(err.Error(), "target URL is required") {
		t.Errorf("missing target: err = %v", err)
	}
	kitParamMineTarget = "ftp://x"
	if err := runKitParamMine(kitParamMineCmd, nil); err == nil || !strings.Contains(err.Error(), "http://") {
		t.Errorf("bad scheme: err = %v", err)
	}
}
