package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
)

// stubLiveness pins the clock, hostname and PID check for one test.
func stubLiveness(t *testing.T, now time.Time, host string, alive func(int) bool) {
	t.Helper()
	prevNow, prevHost, prevAlive := livenessNow, livenessHostname, livenessPIDAlive
	livenessNow = func() time.Time { return now }
	livenessHostname = func() (string, error) { return host, nil }
	livenessPIDAlive = alive
	t.Cleanup(func() { livenessNow, livenessHostname, livenessPIDAlive = prevNow, prevHost, prevAlive })
}

func writeStatusFile(t *testing.T, dir string, st runner.SessionStatus) string {
	t.Helper()
	path := runner.SessionStatusPath(dir, st.ScanUUID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(st)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSessionLivenessTable(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-20 * time.Second)
	old := now.Add(-10 * time.Minute)
	alwaysAlive := func(int) bool { return true }

	type tc struct {
		name        string
		row         *database.Scan
		status      *runner.SessionStatus
		logMTime    time.Time
		lastLog     time.Time
		alive       func(int) bool
		wantStale   bool
		wantGone    *bool
		wantSources []string
		wantLast    time.Time
	}
	gone, notGone := true, false
	cases := []tc{
		{
			name:        "status file fresh",
			status:      &runner.SessionStatus{ScanUUID: "s1", HeartbeatAt: fresh},
			alive:       alwaysAlive,
			wantSources: []string{livenessSourceStatusFile},
			wantLast:    fresh,
		},
		{
			name:        "status file stale",
			status:      &runner.SessionStatus{ScanUUID: "s2", HeartbeatAt: old},
			alive:       alwaysAlive,
			wantStale:   true,
			wantSources: []string{livenessSourceStatusFile},
			wantLast:    old,
		},
		{
			name:        "db heartbeat only, fresh beats an old row",
			row:         &database.Scan{UUID: "s3", Status: "running", HeartbeatAt: &fresh, UpdatedAt: old},
			alive:       alwaysAlive,
			wantSources: []string{livenessSourceHeartbeat, livenessSourceRow},
			wantLast:    fresh,
		},
		{
			name:        "scan_logs only keeps a heartbeat-less row alive",
			row:         &database.Scan{UUID: "s4", Status: "running", UpdatedAt: old},
			lastLog:     fresh,
			alive:       alwaysAlive,
			wantSources: []string{livenessSourceScanLogs, livenessSourceRow},
			wantLast:    fresh,
		},
		{
			name:        "everything old",
			row:         &database.Scan{UUID: "s5", Status: "running", HeartbeatAt: &old, UpdatedAt: old},
			lastLog:     old,
			alive:       alwaysAlive,
			wantStale:   true,
			wantSources: []string{livenessSourceHeartbeat, livenessSourceScanLogs, livenessSourceRow},
			wantLast:    old,
		},
		{
			name:        "pid gone on this host is dead immediately",
			row:         &database.Scan{UUID: "s6", Status: "running", HeartbeatAt: &fresh, UpdatedAt: fresh, PID: 4242, RunnerHost: "here"},
			alive:       func(pid int) bool { return pid != 4242 },
			wantStale:   true,
			wantGone:    &gone,
			wantSources: []string{livenessSourceHeartbeat, livenessSourceRow},
			wantLast:    fresh,
		},
		{
			name:        "pid alive on this host does not clear staleness",
			row:         &database.Scan{UUID: "s7", Status: "running", HeartbeatAt: &old, UpdatedAt: old, PID: 4242, RunnerHost: "here"},
			alive:       alwaysAlive,
			wantStale:   true,
			wantGone:    &notGone,
			wantSources: []string{livenessSourceHeartbeat, livenessSourceRow},
			wantLast:    old,
		},
		{
			name:        "pid on another host is not checked",
			row:         &database.Scan{UUID: "s8", Status: "running", HeartbeatAt: &fresh, UpdatedAt: fresh, PID: 4242, RunnerHost: "elsewhere"},
			alive:       func(int) bool { t.Fatal("must not check a remote pid"); return false },
			wantSources: []string{livenessSourceHeartbeat, livenessSourceRow},
			wantLast:    fresh,
		},
		{
			name:        "status file supplies the pid when there is no row",
			status:      &runner.SessionStatus{ScanUUID: "s9", HeartbeatAt: fresh, PID: 77, Host: "here"},
			alive:       func(int) bool { return false },
			wantStale:   true,
			wantGone:    &gone,
			wantSources: []string{livenessSourceStatusFile},
			wantLast:    fresh,
		},
		{
			name:        "log file mtime",
			logMTime:    fresh,
			alive:       alwaysAlive,
			wantSources: []string{livenessSourceLogFile},
			wantLast:    fresh,
		},
		{
			name:        "no signal at all is not stale",
			alive:       alwaysAlive,
			wantSources: nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stubLiveness(t, now, "here", c.alive)
			dir := t.TempDir()
			statusPath := ""
			if c.status != nil {
				statusPath = writeStatusFile(t, dir, *c.status)
			}
			logPath := ""
			if !c.logMTime.IsZero() {
				logPath = filepath.Join(dir, "runtime.log")
				if err := os.WriteFile(logPath, []byte("x\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(logPath, c.logMTime, c.logMTime); err != nil {
					t.Fatal(err)
				}
			}
			lv := sessionLiveness(c.row, statusPath, logPath, c.lastLog)
			if lv.Stale != c.wantStale {
				t.Errorf("stale = %v, want %v", lv.Stale, c.wantStale)
			}
			if (lv.ProcessGone == nil) != (c.wantGone == nil) || (lv.ProcessGone != nil && *lv.ProcessGone != *c.wantGone) {
				t.Errorf("process_gone = %v, want %v", lv.ProcessGone, c.wantGone)
			}
			if len(lv.Sources) != len(c.wantSources) {
				t.Fatalf("sources = %v, want %v", lv.Sources, c.wantSources)
			}
			for i := range c.wantSources {
				if lv.Sources[i] != c.wantSources[i] {
					t.Errorf("sources = %v, want %v", lv.Sources, c.wantSources)
				}
			}
			if !lv.LastWriteAt.Equal(c.wantLast) {
				t.Errorf("last_write_at = %v, want %v", lv.LastWriteAt, c.wantLast)
			}
		})
	}
}

func TestEffectiveStatus(t *testing.T) {
	stale := Liveness{Stale: true}
	for _, c := range []struct {
		status, msg string
		lv          Liveness
		want        string
	}{
		{"running", "", Liveness{}, "running"},
		{"running", "", stale, "abandoned"},
		{"completed", "", stale, "completed"},
		{"failed", "boom", Liveness{}, "failed"},
		{"failed", "cancelled", Liveness{}, "cancelled"},
		{"", "", stale, ""},
	} {
		if got := effectiveStatus(c.status, c.msg, c.lv); got != c.want {
			t.Errorf("effectiveStatus(%q,%q,stale=%v) = %q, want %q", c.status, c.msg, c.lv.Stale, got, c.want)
		}
	}
}

// log ls rows: typed, with liveness fields; stale only qualifies running.
func TestLogRowViewLiveness(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	stubLiveness(t, now, "here", func(int) bool { return true })
	old := now.Add(-14 * time.Minute)

	live := sessionRow{kind: "native", uuid: "a", status: "running",
		liveness: livenessFromSignals(livenessSignals{heartbeatAt: now.Add(-5 * time.Second)})}
	dead := sessionRow{kind: "native", uuid: "b", status: "running",
		liveness: livenessFromSignals(livenessSignals{heartbeatAt: old})}
	done := sessionRow{kind: "native", uuid: "c", status: "completed",
		liveness: livenessFromSignals(livenessSignals{heartbeatAt: old})}
	cancelled := sessionRow{kind: "native", uuid: "d", status: "failed", errorMessage: "cancelled"}
	agentic := sessionRow{kind: "agentic", uuid: "e", status: "running", liveness: agenticLiveness("", "")}

	if v := live.view(); v.Stale || v.EffectiveStatus != "running" || v.LastWriteAt == nil {
		t.Errorf("live row = %+v", v)
	}
	v := dead.view()
	if !v.Stale || v.EffectiveStatus != "abandoned" || v.Status != "running" {
		t.Errorf("dead row = %+v", v)
	}
	if v.LastWriteAt == nil || *v.LastWriteAt != "2026-10-10T11:46:00.000Z" {
		t.Errorf("last_write_at = %v", v.LastWriteAt)
	}
	if got := fmtStaleAge(dead.liveness.LastWriteAt); got != "14m" {
		t.Errorf("stale age = %q, want 14m", got)
	}
	if v := done.view(); v.Stale || v.EffectiveStatus != "completed" {
		t.Errorf("terminal row = %+v", v)
	}
	if v := cancelled.view(); v.EffectiveStatus != "cancelled" || v.LastWriteAt != nil || v.LivenessSources == nil {
		t.Errorf("cancelled row = %+v", v)
	}
	if v := agentic.view(); v.Stale || v.EffectiveStatus != "running" {
		t.Errorf("agentic row without a log = %+v", v)
	}

	data, err := json.Marshal(dead.view())
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	for _, k := range []string{"last_write_at", "stale", "effective_status", "liveness_sources", "status"} {
		if _, ok := m[k]; !ok {
			t.Errorf("log ls row lacks %q: %s", k, data)
		}
	}
}
