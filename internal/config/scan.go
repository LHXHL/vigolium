package config

import "time"

// RuntimeLogFilename is the fixed filename used for per-session runtime logs
// across native and agentic scans. It lives at {sessions_dir}/{uuid}/<this>.
const RuntimeLogFilename = "runtime.log"

// ScanLogsConfig holds native-scan session log persistence settings.
// Nested under ScanningStrategyConfig as `scan_logs`.
type ScanLogsConfig struct {
	SessionsDir string `yaml:"sessions_dir"`           // directory for native scan session artifacts (default: ~/.vigolium/native-sessions/)
	PersistLogs *bool  `yaml:"persist_logs,omitempty"` // when true, mirror raw console output to {sessions_dir}/{scan_uuid}/run.log (default: false)
	// StatusRetentionDays is how long a scan's status.json heartbeat file is
	// kept after its last write (the scan finished, or died). Nil means
	// DefaultStatusRetentionDays; 0 keeps them forever. Pruned at server start
	// and by `vigolium log ls --reap`; runtime.log is never touched.
	StatusRetentionDays *int `yaml:"status_retention_days,omitempty"`
}

// DefaultStatusRetentionDays is the status.json retention when
// status_retention_days is unset.
const DefaultStatusRetentionDays = 30

// StatusRetention returns how long status.json files are kept after their last
// write; 0 means forever (pruning off).
func (c *ScanLogsConfig) StatusRetention() time.Duration {
	days := DefaultStatusRetentionDays
	if c.StatusRetentionDays != nil {
		days = *c.StatusRetentionDays
	}
	if days <= 0 {
		return 0
	}
	return time.Duration(days) * 24 * time.Hour
}

// IsPersistLogsEnabled returns whether run.log persistence is enabled. Defaults to false.
func (c *ScanLogsConfig) IsPersistLogsEnabled() bool {
	return c.PersistLogs != nil && *c.PersistLogs
}

// EffectiveSessionsDir returns the sessions directory, defaulting to ~/.vigolium/native-sessions/.
func (c *ScanLogsConfig) EffectiveSessionsDir() string {
	if c.SessionsDir != "" {
		return ExpandPath(c.SessionsDir)
	}
	return ExpandPath("~/.vigolium/native-sessions/")
}

// DefaultScanLogsConfig returns sensible defaults (persistence disabled, default sessions dir).
func DefaultScanLogsConfig() *ScanLogsConfig {
	return &ScanLogsConfig{
		SessionsDir: "~/.vigolium/native-sessions/",
	}
}
