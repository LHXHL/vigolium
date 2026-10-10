package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

// The status → event mapping a receiver relies on.
func TestNativeEventMapping(t *testing.T) {
	cases := []struct {
		status, errMsg, stopReason string
		event, outStatus           string
		terminal                   bool
	}{
		{"completed", "", "", EventScanCompleted, "completed", true},
		{"", "", "", EventScanCompleted, "completed", true},
		// A curtailed scan reached its end: still scan.completed.
		{"completed", "", database.ReasonScanBudget, EventScanCompleted, "completed", true},
		{"failed", "boom", database.ReasonError, EventScanFailed, "failed", true},
		{"failed", "scope admitted no target", database.ReasonNoTargetsInScope, EventScanFailed, "failed", true},
		// The runner stores an interrupt as failed/"cancelled".
		{"failed", "cancelled", database.ReasonCancelled, EventScanCancelled, "cancelled", true},
		{"failed", "cancelled", "", EventScanCancelled, "cancelled", true},
		{"failed", "", database.ReasonCancelled, EventScanCancelled, "cancelled", true},
		{"cancelled", "", "", EventScanCancelled, "cancelled", true},
		// Not an end state: reported verbatim as before.
		{"running", "", "", EventScanCompleted, "running", false},
	}
	for _, c := range cases {
		event, st, terminal := NativeEvent(c.status, c.errMsg, c.stopReason)
		assert.Equal(t, c.event, event, "status=%q err=%q reason=%q", c.status, c.errMsg, c.stopReason)
		assert.Equal(t, c.outStatus, st, "status=%q", c.status)
		assert.Equal(t, c.terminal, terminal, "status=%q", c.status)
	}
}

func TestAgenticEventMapping(t *testing.T) {
	cases := []struct {
		status, event, completeness, stopReason string
	}{
		{"completed", EventScanCompleted, "", ""},
		{"completed_with_warnings", EventScanCompleted, "", ""},
		{"completed_with_errors", EventScanCompleted, "", ""},
		{"timeout", EventScanCompleted, database.CompletenessPartial, "timeout"},
		{"budget_exhausted", EventScanCompleted, database.CompletenessPartial, "budget_exhausted"},
		{"cancelled", EventScanCancelled, database.CompletenessPartial, database.ReasonCancelled},
		{"failed", EventScanFailed, database.CompletenessPartial, database.ReasonError},
		{"error", EventScanFailed, database.CompletenessPartial, database.ReasonError},
		{"running", EventScanCompleted, "", ""},
	}
	for _, c := range cases {
		event, completeness, reason := AgenticEvent(c.status)
		assert.Equal(t, c.event, event, c.status)
		assert.Equal(t, c.completeness, completeness, c.status)
		assert.Equal(t, c.stopReason, reason, c.status)
	}
}

// With no row, the caller's outcome decides; with nothing to say, nothing fires.
func TestNativeScanPayloadWithoutRow(t *testing.T) {
	_, ok := NativeScanPayload("s1", nil, Outcome{})
	assert.False(t, ok, "no row and no outcome: nothing to report")

	p, ok := NativeScanPayload("s1", nil, Outcome{Err: errors.New("session login failed"), Target: "https://t.example", ProjectUUID: "p1"})
	require.True(t, ok)
	assert.Equal(t, EventScanFailed, p.Event)
	assert.Equal(t, "failed", p.Status)
	assert.Equal(t, "session login failed", p.Error)
	assert.Equal(t, "s1", p.ScanUUID)
	assert.Equal(t, "p1", p.ProjectUUID)
	assert.Equal(t, "https://t.example", p.Target)
	assert.Equal(t, database.CompletenessPartial, p.Completeness)
	assert.Len(t, p.Findings.BySeverity, 5)

	p, ok = NativeScanPayload("s1", nil, Outcome{Interrupted: true, Err: errors.New("x")})
	require.True(t, ok)
	assert.Equal(t, EventScanCancelled, p.Event)
	assert.Equal(t, database.ReasonCancelled, p.StopReason)

	// A row stuck non-terminal defers to the caller's view.
	p, ok = NativeScanPayload("s1", &database.Scan{UUID: "s1", Status: "running"}, Outcome{Interrupted: true})
	require.True(t, ok)
	assert.Equal(t, EventScanCancelled, p.Event)
	assert.Equal(t, "cancelled", p.Status)

	// A terminal row wins over the caller's view.
	p, ok = NativeScanPayload("s1", &database.Scan{UUID: "s1", Status: "completed", Completeness: "complete"}, Outcome{Err: errors.New("export failed")})
	require.True(t, ok)
	assert.Equal(t, EventScanCompleted, p.Event)
	assert.Empty(t, p.Error)
	assert.Equal(t, "complete", p.Completeness)
}

func TestWebhookConfigEvents(t *testing.T) {
	var w config.WebhookConfig
	for _, e := range []string{EventScanCompleted, EventScanFailed, EventScanCancelled} {
		assert.True(t, w.AllowsEvent(e), "unset events allows %s", e)
	}
	w.Events = []string{"completed"}
	assert.True(t, w.AllowsEvent(EventScanCompleted))
	assert.False(t, w.AllowsEvent(EventScanFailed))
	w.Events = []string{"scan.failed", "Cancelled"}
	assert.False(t, w.AllowsEvent(EventScanCompleted))
	assert.True(t, w.AllowsEvent(EventScanFailed))
	assert.True(t, w.AllowsEvent(EventScanCancelled))
	assert.NoError(t, w.Validate())
	w.Events = []string{"finished"}
	assert.Error(t, w.Validate())
}

// receiver records each POSTed payload.
type receiver struct {
	srv   *httptest.Server
	mu    sync.Mutex
	got   []ScanCompletedPayload
	delay time.Duration
}

func newReceiver(t *testing.T, delay time.Duration) *receiver {
	t.Helper()
	r := &receiver{delay: delay}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		time.Sleep(r.delay)
		var p ScanCompletedPayload
		_ = json.NewDecoder(req.Body).Decode(&p)
		r.mu.Lock()
		r.got = append(r.got, p)
		r.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *receiver) payloads() []ScanCompletedPayload {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]ScanCompletedPayload(nil), r.got...)
}

func webhookSettings(url string, events ...string) *config.Settings {
	s := config.DefaultSettings()
	s.Notify.Enabled = true
	s.Notify.Provider = config.NotifyProviderWebhook
	s.Notify.Webhook = config.WebhookConfig{URL: url, TimeoutSec: 5, Events: events}
	return s
}

// Drain returns only once the asynchronous POST landed.
func TestDrainDeliversBeforeReturn(t *testing.T) {
	r := newReceiver(t, 200*time.Millisecond)
	NewSender(config.WebhookConfig{URL: r.srv.URL, TimeoutSec: 5}).PostAsync(ScanCompletedPayload{Event: EventScanCompleted, ScanUUID: "s1"})
	assert.Equal(t, 0, Drain(5*time.Second))
	require.Len(t, r.payloads(), 1)
	assert.Equal(t, "s1", r.payloads()[0].ScanUUID)
}

// A receiver that does not answer in time is reported, not waited out.
func TestDrainBounded(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release); Drain(5 * time.Second) })

	NewSender(config.WebhookConfig{URL: srv.URL, TimeoutSec: 5}).PostAsync(ScanCompletedPayload{Event: EventScanCompleted})
	start := time.Now()
	assert.Equal(t, 1, Drain(100*time.Millisecond))
	assert.Less(t, time.Since(start), 2*time.Second)
}

func newRepo(t *testing.T) *database.Repository {
	t.Helper()
	db, err := database.NewDB(&config.DatabaseConfig{
		Enabled: true,
		Driver:  "sqlite",
		SQLite:  config.SQLiteConfig{Path: filepath.Join(t.TempDir(), "w.sqlite"), BusyTimeout: 5000, JournalMode: "WAL", Synchronous: "NORMAL", CacheSize: 1000},
	})
	require.NoError(t, err)
	require.NoError(t, db.CreateSchema(context.Background()))
	t.Cleanup(func() { _ = db.Close() })
	return database.NewRepository(db)
}

// End to end from a stored row: the row's terminal state picks the event, and
// notify.webhook.events filters it.
func TestFireNativeScanFromRow(t *testing.T) {
	repo := newRepo(t)
	ctx := context.Background()
	mk := func(id, errMsg string, c database.ScanCompletion) {
		require.NoError(t, repo.CreateScan(ctx, database.NewSingleRequestScan(id, "p1", database.ScanNameScanURL, "https://t.example", "", "cli")))
		require.NoError(t, repo.CompleteScanWithOutcome(ctx, id, errMsg, c))
	}
	mk("ok", "", database.ScanCompletion{Completeness: database.CompletenessPartial, StopReason: database.ReasonScanBudget})
	mk("bad", "boom", database.ScanCompletion{Completeness: database.CompletenessPartial, StopReason: database.ReasonError})
	mk("stop", "cancelled", database.ScanCompletion{Completeness: database.CompletenessPartial, StopReason: database.ReasonCancelled})

	r := newReceiver(t, 0)
	settings := webhookSettings(r.srv.URL)
	for _, id := range []string{"ok", "bad", "stop", "missing"} {
		FireNativeScan(settings, repo, id)
	}
	require.Equal(t, 0, Drain(5*time.Second))
	byID := map[string]ScanCompletedPayload{}
	for _, p := range r.payloads() {
		byID[p.ScanUUID] = p
	}
	require.Len(t, byID, 3, "a missing row with no outcome fires nothing")
	assert.Equal(t, EventScanCompleted, byID["ok"].Event)
	assert.Equal(t, database.CompletenessPartial, byID["ok"].Completeness)
	assert.Equal(t, database.ReasonScanBudget, byID["ok"].StopReason)
	assert.Equal(t, EventScanFailed, byID["bad"].Event)
	assert.Equal(t, "boom", byID["bad"].Error)
	assert.Equal(t, EventScanCancelled, byID["stop"].Event)
	assert.Equal(t, "cancelled", byID["stop"].Status)
	assert.Equal(t, "p1", byID["stop"].ProjectUUID)

	// Filtered: only failures.
	r2 := newReceiver(t, 0)
	settings = webhookSettings(r2.srv.URL, "failed")
	for _, id := range []string{"ok", "bad", "stop"} {
		FireNativeScan(settings, repo, id)
	}
	require.Equal(t, 0, Drain(5*time.Second))
	got := r2.payloads()
	require.Len(t, got, 1)
	assert.Equal(t, "bad", got[0].ScanUUID)
}
