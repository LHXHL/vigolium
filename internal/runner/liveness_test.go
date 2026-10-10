package runner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

// fakeClock is a settable time source for the heartbeat.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func readStatus(t *testing.T, dir, uuid string) *SessionStatus {
	t.Helper()
	st, err := ReadSessionStatus(SessionStatusPath(dir, uuid))
	if err != nil || st == nil {
		t.Fatalf("read status.json: %v (nil=%v)", err, st == nil)
	}
	return st
}

func TestHeartbeatLifecycle(t *testing.T) {
	dir := t.TempDir()
	clock := &fakeClock{now: time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)}
	var sent atomic.Int64
	var extra atomic.Int64
	total := int64(100)

	h := StartHeartbeat(HeartbeatConfig{
		ScanUUID:        "scan-1",
		SessionsDir:     dir,
		ProjectUUID:     "proj",
		PhasesPlanned:   []string{"discovery", "dynamic-assessment"},
		ScanMaxDuration: 30 * time.Minute,
		Requests:        func() int64 { return sent.Load() + extra.Load() },
		Progress:        func() *SessionProgress { return &SessionProgress{Done: 40, Total: &total, Unit: "records"} },
		Interval:        time.Hour, // beats in this test are explicit
		Now:             clock.Now,
	})

	// The first beat is synchronous: a reader looking right after start finds it.
	st := readStatus(t, dir, "scan-1")
	if st.Status != SessionRunning || st.PID != os.Getpid() || st.Host == "" || st.ScanMaxDurationMS != 30*60*1000 {
		t.Fatalf("first beat = %+v", st)
	}
	if st.PhasesDone == nil {
		t.Error("phases_done must be [] not null")
	}

	h.PhaseStarted("discovery")
	sent.Store(10)
	extra.Store(5) // a phase-local counter (deparos) while discovery runs
	h.RecordFinding("High")
	h.RecordFinding("low")
	clock.Advance(10 * time.Second)
	h.beat(context.Background(), false)

	st = readStatus(t, dir, "scan-1")
	if st.Phase != "discovery" || st.RequestsSent != 15 || st.Findings != 2 || st.FindingsBySeverity["high"] != 1 {
		t.Fatalf("mid-phase beat = %+v", st)
	}
	if st.Progress == nil || st.Progress.Done != 40 || st.Progress.Total == nil || *st.Progress.Total != 100 {
		t.Fatalf("progress = %+v", st.Progress)
	}
	if !st.HeartbeatAt.Equal(clock.Now()) {
		t.Errorf("heartbeat_at = %v, want %v", st.HeartbeatAt, clock.Now())
	}

	// Phase ends: its extra counter is folded in so the scan-wide figure holds
	// once the Requests func stops seeing it.
	h.PhaseEnded("discovery", extra.Load())
	extra.Store(0)
	h.beat(context.Background(), false)
	st = readStatus(t, dir, "scan-1")
	if st.Phase != "" || st.RequestsSent != 15 || len(st.PhasesDone) != 1 || st.Progress != nil {
		t.Fatalf("after phase end = %+v", st)
	}

	h.Finish(SessionCompleted)
	h.Finish(SessionFailed) // idempotent stop; status can still be corrected
	st = readStatus(t, dir, "scan-1")
	if st.Status != SessionFailed {
		t.Fatalf("final status = %q", st.Status)
	}
}

// A concurrent reader never sees a torn status.json: every read parses.
func TestHeartbeatStatusFileAtomic(t *testing.T) {
	dir := t.TempDir()
	h := StartHeartbeat(HeartbeatConfig{ScanUUID: "scan-atomic", SessionsDir: dir, Interval: time.Hour})
	defer h.Finish(SessionCompleted)

	path := SessionStatusPath(dir, "scan-atomic")
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			h.PhaseStarted("phase-with-a-longer-name-" + string(rune('a'+i%26)))
			h.beat(context.Background(), false)
		}
	}()

	deadline := time.Now().Add(300 * time.Millisecond)
	reads := 0
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var st SessionStatus
		if err := json.Unmarshal(data, &st); err != nil {
			t.Fatalf("torn read after %d reads: %v\n%s", reads, err, data)
		}
		reads++
	}
	close(stop)
	wg.Wait()
	if reads == 0 {
		t.Fatal("no reads")
	}
}

func TestHeartbeatNilSafe(t *testing.T) {
	var h *Heartbeat
	h.PhaseStarted("x")
	h.PhaseEnded("x", 1)
	h.RecordFinding("high")
	h.Stop(context.Background())
	h.Finish(SessionCompleted)

	var tr *phaseTracker
	if tr.extraSentSoFar() != 0 || tr.progressSnapshot() != nil {
		t.Fatal("nil tracker must report nothing")
	}
}

func TestReadSessionStatusMissing(t *testing.T) {
	st, err := ReadSessionStatus(SessionStatusPath(t.TempDir(), "nope"))
	if st != nil || err != nil {
		t.Fatalf("missing file = %v, %v; want nil, nil", st, err)
	}
}

// A direct-path heartbeat stamps its running row and ends itself once someone
// else finalizes the row, recording the row's status in status.json.
func TestHeartbeatStopsWhenRowDone(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := database.NewDB(&config.DatabaseConfig{
		Enabled: true, Driver: "sqlite",
		SQLite: config.SQLiteConfig{Path: filepath.Join(dir, "hb.sqlite"), BusyTimeout: 5000, JournalMode: "WAL", Synchronous: "NORMAL"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if err := db.CreateSchema(ctx); err != nil {
		t.Fatal(err)
	}
	repo := database.NewRepository(db)
	if err := repo.CreateScan(ctx, &database.Scan{UUID: "direct-1", Status: "running", StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	h := StartHeartbeat(HeartbeatConfig{Repo: repo, ScanUUID: "direct-1", SessionsDir: dir,
		Phase: "dynamic-assessment", StopWhenRowDone: true, Interval: 20 * time.Millisecond})
	defer h.Stop(ctx)

	row, _ := repo.GetScanByUUID(ctx, "direct-1")
	if row.HeartbeatAt == nil || row.PID != os.Getpid() || row.CurrentPhase != "dynamic-assessment" || row.TotalRequests != 0 {
		t.Fatalf("first beat on the row = %+v", row)
	}

	if err := repo.CompleteScan(ctx, "direct-1", "cancelled"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.done:
	case <-time.After(5 * time.Second):
		t.Fatal("heartbeat did not stop after its row was finalized")
	}
	if st := readStatus(t, dir, "direct-1"); st.Status != SessionCancelled {
		t.Fatalf("status.json status = %q, want cancelled", st.Status)
	}
}
