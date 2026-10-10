package runner

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
	vighttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

func TestParamMiningGate(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts types.Options
		skip []string
		want bool
	}{
		{name: "balanced default", opts: types.Options{Intensity: "balanced"}, want: false},
		{name: "deep", opts: types.Options{Intensity: "deep"}, want: true},
		{name: "--param-mining below deep", opts: types.Options{Intensity: "quick", ParamMining: boolPtr(true)}, want: true},
		{name: "--param-mining=false at deep", opts: types.Options{Intensity: "deep", ParamMining: boolPtr(false)}, want: false},
		{name: "deep without an assessment", opts: types.Options{Intensity: "deep", SkipDynamicAssessment: true}, want: false},
		{name: "--param-mining without an assessment", opts: types.Options{ParamMining: boolPtr(true), SkipDynamicAssessment: true}, want: false},
		{name: "--skip param-mining at deep", opts: types.Options{Intensity: "deep"}, skip: []string{"param-mining"}, want: false},
		{name: "--skip arjun", opts: types.Options{ParamMining: boolPtr(true)}, skip: []string{"arjun"}, want: false},
		{name: "deep under --only", opts: types.Options{Intensity: "deep", OnlyPhase: "dast"}, want: false},
		{name: "--param-mining under --only", opts: types.Options{OnlyPhase: "dast", ParamMining: boolPtr(true)}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.opts
			opts.SkipPhases = tc.skip
			if err := ApplyNativePhaseSelection(&opts, nil); err != nil {
				t.Fatalf("ApplyNativePhaseSelection: %v", err)
			}
			if got := planStepEnabled(BuildNativeScanPlan(&opts), PhaseParamMining); got != tc.want {
				t.Errorf("param-mining enabled = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestParamMiningPlacement: the step runs after everything that stores records
// (re-spider, seed) and right before the assessment that consumes its output.
func TestParamMiningPlacement(t *testing.T) {
	steps := BuildNativeScanPlan(&types.Options{}).Steps
	idx := map[NativePhase]int{}
	for i, s := range steps {
		idx[s.Phase] = i
	}
	pm, ok := idx[PhaseParamMining]
	if !ok {
		t.Fatal("param-mining is not a plan step")
	}
	if pm < idx[PhaseTargetedReSpider] || pm < idx[PhaseSeed] || pm+1 != idx[PhaseDynamicAssessment] {
		t.Errorf("param-mining at %d; want after targeted-respider (%d) and seed (%d), directly before dynamic-assessment (%d)",
			pm, idx[PhaseTargetedReSpider], idx[PhaseSeed], idx[PhaseDynamicAssessment])
	}
	if steps[pm].SkipsTarget {
		t.Error("param-mining sends requests; it must not be marked SkipsTarget")
	}
}

func TestParamMiningVocabulary(t *testing.T) {
	for _, alias := range []string{"param-mining", "params", "arjun", "param-miner", "ARJUN"} {
		if got := NormalizeNativePhase(alias); got != string(PhaseParamMining) {
			t.Errorf("NormalizeNativePhase(%q) = %q", alias, got)
		}
		if !IsSkippablePhaseSpelling(alias) {
			t.Errorf("--skip %s rejected", alias)
		}
		if IsOnlyPhaseSpelling(alias) {
			t.Errorf("--only %s accepted; param-mining is internal", alias)
		}
	}
}

func TestSelectParamMiningEndpoints(t *testing.T) {
	rec := func(method, path, respCT, reqCT string) database.HTTPRecord {
		return database.HTTPRecord{Scheme: "https", Hostname: "app.test", Port: 443, Method: method, Path: path,
			ResponseContentType: respCT, RequestContentType: reqCT}
	}
	rows := []database.HTTPRecord{
		rec("GET", "/search?q=1", "text/html", ""),
		rec("GET", "/search?q=2", "text/html", ""), // same endpoint
		rec("GET", "/app.js", "application/javascript", ""),
		rec("GET", "/logo", "image/png", ""),
		rec("GET", "/assets/data", "application/json", ""),
		rec("GET", "/api/items", "application/json; charset=utf-8", ""),
		rec("POST", "/api/items", "application/json", "application/json"),
		rec("POST", "/upload", "text/html", "application/octet-stream"),
		rec("GET", "/feed", "application/rss+xml", ""),
		rec("GET", "/download", "application/octet-stream", ""),
	}
	var got []string
	for _, ep := range selectParamMiningEndpoints(rows, 0) {
		got = append(got, ep.record.Method+" "+ep.record.Path)
	}
	want := []string{"GET /search?q=1", "GET /api/items", "POST /api/items", "GET /feed"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("selected %v, want %v", got, want)
	}
	if n := len(selectParamMiningEndpoints(rows, 2)); n != 2 {
		t.Errorf("per-host cap 2 selected %d", n)
	}
}

// TestParamMiningPhase_StoresHiddenParamRecord runs the phase against a local
// app whose hidden parameter appears nowhere but in a jstangle-derived record:
// the host's own names are mined, and the confirmed parameter lands as a
// param-mining record (remark, hidden flag, scan stamp) for the assessment.
func TestParamMiningPhase_StoresHiddenParamRecord(t *testing.T) {
	var hits atomic.Int64
	page := strings.Repeat("<p>catalogue entry with ordinary descriptive text</p>\n", 25)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		body := "<html>" + page
		if r.URL.Query().Has("vgsecretflag") {
			body += strings.Repeat("<pre>internal state dump: cache=warm shard=7</pre>\n", 15)
		}
		_, _ = io.WriteString(w, body+"</html>")
	}))
	t.Cleanup(srv.Close)

	opts := types.DefaultOptions()
	opts.Silent = true
	opts.Retries = 0
	opts.Concurrency = 2
	opts.ProjectUUID = database.DefaultProjectUUID
	opts.Targets = []string{srv.URL}
	if err := network.Init(opts); err != nil {
		t.Fatalf("network.Init: %v", err)
	}
	requester, err := vighttp.NewRequester(opts, &services.Services{Options: opts})
	if err != nil {
		t.Fatalf("NewRequester: %v", err)
	}
	repo, _ := newHarvestTestRepo(t)
	ctx := context.Background()
	const scanID = "param-mining-test"
	if err := repo.CreateScan(ctx, &database.Scan{UUID: scanID, ProjectUUID: opts.ProjectUUID, Status: "running", StartedAt: time.Now()}); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}

	// The endpoint, as discovery would have stored it.
	rr, err := httpmsg.GetRawRequestFromURL(srv.URL + "/catalog?page=1")
	if err != nil {
		t.Fatal(err)
	}
	resp := httpmsg.NewHttpResponse(httpmsg.BuildRawResponse(200, map[string]string{"Content-Type": "text/html"}, "<html>"+page+"</html>"))
	if _, err := repo.SaveRecord(ctx, rr.WithResponse(resp), "discovery", opts.ProjectUUID); err != nil {
		t.Fatalf("save endpoint: %v", err)
	}
	// A request-only JS template naming the hidden parameter.
	js, err := httpmsg.GetRawRequestFromURL(srv.URL + "/api/state?vgsecretflag=1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.SaveRecord(ctx, js, "jstangle", opts.ProjectUUID); err != nil {
		t.Fatalf("save jstangle stub: %v", err)
	}

	settings := config.DefaultSettings()
	r := &Runner{options: opts, repository: repo, settings: settings}
	tr := newLedger(string(PhaseParamMining))
	r.currentPhase.Store(tr)
	if err := r.runParamMiningPhase(ctx, &phaseInfra{httpRequester: requester, scanUUID: scanID}); err != nil {
		t.Fatalf("runParamMiningPhase: %v", err)
	}

	out := tr.outcome()
	if out.Counts[paramMiningCountEndpoints] != 1 || out.Counts[paramMiningCountFound] != 1 || out.Counts[paramMiningCountRecords] != 1 {
		t.Fatalf("counts = %v; want 1 endpoint, 1 param, 1 record", out.Counts)
	}
	if n := hits.Load(); n > int64(config.DefaultParamMiningRequestsPerEnd) {
		t.Errorf("phase sent %d requests, over the per-endpoint budget", n)
	}

	rows, err := repo.ParamMiningCandidates(ctx, scanID, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Source == database.RecordSourceParamMining {
			t.Errorf("param-mining output %s offered as a candidate again", row.URL)
		}
	}

	var stored []database.HTTPRecord
	if err := repo.DB().NewSelect().Model(&stored).Where("source = ?", database.RecordSourceParamMining).Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 {
		t.Fatalf("param-mining records = %d, want 1", len(stored))
	}
	got := stored[0]
	if !strings.Contains(got.URL, "vgsecretflag=") || !strings.Contains(got.URL, "page=1") {
		t.Errorf("stored URL %q should carry the original query and the hidden parameter", got.URL)
	}
	if got.ScanUUID != scanID {
		t.Errorf("scan_uuid = %q, want %q", got.ScanUUID, scanID)
	}
	if len(got.Remarks) != 1 || got.Remarks[0] != "param-mining:name=vgsecretflag;signal=length" {
		t.Errorf("remarks = %v", got.Remarks)
	}
	hidden := map[string]bool{}
	for _, p := range got.Parameters {
		hidden[p.Name] = p.Hidden
	}
	if !hidden["vgsecretflag"] || hidden["page"] {
		t.Errorf("hidden flags = %v; want only vgsecretflag hidden", hidden)
	}
}
