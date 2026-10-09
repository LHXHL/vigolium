package runner

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/harvester"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/types"
)

// fakeArchive is a harvester.Source that "finds" a fixed URL list, standing in
// for Wayback/CommonCrawl so the test never leaves the machine.
type fakeArchive struct{ urls []string }

func (f fakeArchive) Name() string   { return "fake-archive" }
func (f fakeArchive) NeedsKey() bool { return false }
func (f fakeArchive) Run(ctx context.Context, _ string) <-chan harvester.Result {
	ch := make(chan harvester.Result, len(f.urls))
	for _, u := range f.urls {
		ch <- harvester.Result{Source: f.Name(), URL: u}
	}
	close(ch)
	return ch
}

func newHarvestTestRepo(t *testing.T) (*database.Repository, *database.DB) {
	t.Helper()
	sqldb, err := sql.Open(sqliteshim.ShimName, ":memory:?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	// :memory: is per-connection — pin to one so schema and writes are visible.
	sqldb.SetMaxOpenConns(1)
	db := database.NewDBFromBun(bun.NewDB(sqldb, sqlitedialect.New()), "sqlite")
	if err := db.CreateSchema(context.Background()); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return database.NewRepository(db), db
}

// TestExternalHarvest_NeverContactsTarget is the regression guard for the
// harvest honesty bug: external-harvest is planned as target-silent
// (SkipsTarget), yet it fetched a baseline for every archived URL from the live
// target. A harvest-only run must send zero requests to the target and still
// leave every harvested URL in the store, as a request-only stub labelled
// source=harvest.
func TestExternalHarvest_NeverContactsTarget(t *testing.T) {
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	urls := []string{
		target.URL + "/",
		target.URL + "/admin/login",
		target.URL + "/api/v1/users?id=1",
		target.URL + "/api/v1/users?id=1", // duplicate: the harvester dedups it
	}
	h := harvester.New([]harvester.Source{fakeArchive{urls: urls}}, time.Minute)
	src := source.NewExternalHarvesterInputSource(h, []string{"127.0.0.1"}, nil)

	repo, db := newHarvestTestRepo(t)
	opts := types.DefaultOptions()
	opts.Targets = []string{target.URL}
	opts.ProjectUUID = database.DefaultProjectUUID
	r := &Runner{options: opts, repository: repo}

	stored, err := r.ingestHarvestStubs(context.Background(), &phaseInfra{scanUUID: "harvest-test"}, src)
	if err != nil {
		t.Fatalf("ingestHarvestStubs: %v", err)
	}

	if got := hits.Load(); got != 0 {
		t.Fatalf("harvest-only run sent %d request(s) to the target, want 0", got)
	}
	if stored != 3 {
		t.Errorf("stored = %d, want 3 (unique harvested URLs)", stored)
	}

	var records []database.HTTPRecord
	if err := db.NewSelect().Model(&records).Scan(context.Background()); err != nil {
		t.Fatalf("select records: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("records = %d, want 3", len(records))
	}
	for _, rec := range records {
		if rec.Source != harvestRecordSource {
			t.Errorf("record %s source = %q, want %q", rec.URL, rec.Source, harvestRecordSource)
		}
		if rec.HasResponse || rec.StatusCode != 0 {
			t.Errorf("record %s has a response (status=%d hasResp=%v); a harvest stub must be request-only",
				rec.URL, rec.StatusCode, rec.HasResponse)
		}
	}
}

// A capped archive index must surface as a phase limit, not look complete.
func TestExternalHarvest_ReportsCDXLimit(t *testing.T) {
	r := &Runner{options: &types.Options{}}
	tr := newLedger("external-harvest")
	r.currentPhase.Store(tr)

	r.reportHarvestShaping(harvester.Stats{Raw: 10, Kept: 4, OverShape: 6, Limits: []string{harvester.LimitCDXMaxRows}})

	out := tr.finish(context.Background(), nil)
	if !slices.Equal(out.Limits, []string{database.LimitCDXMaxRows}) {
		t.Errorf("Limits = %v, want [%s]", out.Limits, database.LimitCDXMaxRows)
	}
}
