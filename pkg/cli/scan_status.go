package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var scanStatusCmd = &cobra.Command{
	Use:   "status <scan-uuid>",
	Short: "Show a scan's live status: phase, progress, liveness and ETA",
	Long: `Show where a native scan is: its status, whether the process behind a
"running" row is still alive, the phase it is in, requests sent, findings by
severity, work-item progress and an ETA.

Liveness combines every signal the scan leaves: the runner's heartbeat
(status.json in the native session directory and the scan row's heartbeat
columns, refreshed every 10s), runtime.log, and the newest scan_logs line. A
running row that has written nothing for 2 minutes — or whose process is
confirmed gone on this host — reports effective_status "abandoned".

The ETA is never invented: upper_bound_ms is the remaining --scanning-max-duration
budget, estimate_ms extrapolates the current phase's rate when it is the last
phase and its total is known; either is null when there is no basis for it.

Reads the database like 'vigolium log' (-S/--db, --glob-db), and falls back to
status.json alone for a -S or --db-isolate scan whose row is not in that store.`,
	Example: FormatExamples(
		"# Where is this scan, and is it still alive?",
		"vigolium scan status 7c0e…-uuid",
		"# Machine-readable (one item)",
		"vigolium scan status 7c0e…-uuid -j",
	),
	Args: cobra.ExactArgs(1),
	RunE: runScanStatus,
}

func init() {
	scanCmd.AddCommand(scanStatusCmd)
	f := scanStatusCmd.Flags()
	f.BoolVarP(&globalStateless, "stateless", "S", false, "Read from --db (a .jsonl export or standalone .sqlite) with project scoping off")
	f.StringVar(&globalGlobDB, "glob-db", "", "Read across a glob of result files merged into one temporary DB (e.g. --glob-db 'scans/*.sqlite'); implies -S")
}

// scanStatusView is one `scan status` item, and the document `scan wait`
// prints when the scan ends.
type scanStatusView struct {
	ScanUUID string `json:"scan_uuid"`
	// Status is the stored status (the row's, else status.json's).
	Status string `json:"status"`
	// EffectiveStatus is what to act on: running | abandoned | completed |
	// failed | cancelled.
	EffectiveStatus    string            `json:"effective_status"`
	Liveness           scanLivenessView  `json:"liveness"`
	Phase              string            `json:"phase,omitempty"`
	PhaseStartedAt     *string           `json:"phase_started_at,omitempty"`
	PhasesDone         []string          `json:"phases_done"`
	PhasesPlanned      []string          `json:"phases_planned,omitempty"`
	RequestsSent       int64             `json:"requests_sent"`
	Findings           int               `json:"findings"`
	FindingsBySeverity map[string]int    `json:"findings_by_severity"`
	Progress           *scanProgressView `json:"progress"`
	ETA                scanETAView       `json:"eta"`
	Completeness       string            `json:"completeness,omitempty"`
	StopReason         string            `json:"stop_reason,omitempty"`
	ErrorMessage       string            `json:"error_message,omitempty"`
	StartedAt          *string           `json:"started_at"`
	FinishedAt         *string           `json:"finished_at,omitempty"`
	DurationMS         int64             `json:"duration_ms"`
	PID                int               `json:"pid,omitempty"`
	RunnerHost         string            `json:"runner_host,omitempty"`
	ProjectUUID        string            `json:"project_uuid,omitempty"`
	DBPath             string            `json:"db_path,omitempty"`
	// Source says where the facts came from: "db", "status_file" or both.
	Source []string `json:"source"`

	// startedAt and phaseStarted are the parsed times the ETA is computed from.
	startedAt    time.Time
	phaseStarted time.Time
	budgetMS     int64
}

type scanLivenessView struct {
	LastWriteAt *string  `json:"last_write_at"`
	Stale       bool     `json:"stale"`
	Sources     []string `json:"sources"`
	ProcessGone *bool    `json:"process_gone,omitempty"`
}

type scanProgressView struct {
	Done  int64  `json:"done"`
	Total *int64 `json:"total"`
	Unit  string `json:"unit"`
}

// scanETAView is the remaining-time estimate. Both figures are null when
// unknowable; basis names what they rest on.
type scanETAView struct {
	EstimateMS   *int64 `json:"estimate_ms"`
	UpperBoundMS *int64 `json:"upper_bound_ms"`
	// Basis: "finished", "phase_rate", "scan_budget", "phase_rate+scan_budget"
	// or "unknown".
	Basis string `json:"basis"`
}

// Effective statuses.
const (
	effStatusRunning   = "running"
	effStatusAbandoned = "abandoned"
	effStatusCompleted = "completed"
	effStatusFailed    = "failed"
	effStatusCancelled = "cancelled"
)

// isTerminalEffectiveStatus reports whether status ends a `scan wait`.
func isTerminalEffectiveStatus(status string) bool {
	switch status {
	case effStatusCompleted, effStatusFailed, effStatusCancelled:
		return true
	}
	return false
}

func runScanStatus(cmd *cobra.Command, args []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()

	uuid := strings.TrimSpace(args[0])
	if uuid == "" {
		return usageErrorf("scan status needs a scan UUID")
	}
	reader, err := newScanStatusReader()
	if err != nil {
		return err
	}
	view, err := reader.read(context.Background(), uuid)
	if err != nil {
		return err
	}
	if globalJSON {
		return emitObject(cmd, "", view, withDBPath(view.DBPath), withQuery("log", uuid))
	}
	printScanStatusHuman(os.Stdout, view)
	return nil
}

// scanStatusReader resolves scan status views. It holds the store (nil when it
// could not be opened — status.json may still answer) and the sessions root.
type scanStatusReader struct {
	repo        *database.Repository
	dbErr       error
	sessionsDir string
	dbPath      string
}

// newScanStatusReader opens the read handle (read pool: polling must never take
// the write lock a running scan needs) and resolves the sessions directory.
func newScanStatusReader() (*scanStatusReader, error) {
	settings, err := clicommon.LoadSettings(globalConfig)
	if err != nil {
		return nil, err
	}
	r := &scanStatusReader{sessionsDir: settings.ScanningStrategy.ScanLogs.EffectiveSessionsDir()}
	db, err := openReadDB(globDBSkipSet{Records: true})
	if err != nil {
		// A usage error (-S without --db) is the caller's to fix; anything else
		// leaves status.json to answer for a scan whose row is elsewhere.
		var usage usageError
		if errors.As(err, &usage) {
			return nil, err
		}
		r.dbErr = err
		return r, nil
	}
	r.repo = database.NewRepository(db)
	r.dbPath = resolvedReadDBPath()
	return r, nil
}

// read builds the view for uuid from the row and status.json. Not found in
// either is a not_found error.
func (r *scanStatusReader) read(ctx context.Context, uuid string) (*scanStatusView, error) {
	var row *database.Scan
	if r.repo != nil {
		err := database.RetryBusy(ctx, func() error {
			var getErr error
			row, getErr = r.repo.GetScanByUUID(ctx, uuid)
			return getErr
		}, database.RetryPolicy{Op: "read scan", MaxAttempts: 5, BaseDelay: 50 * time.Millisecond, MaxDelay: 500 * time.Millisecond})
		switch {
		case err == nil:
		case errors.Is(err, sql.ErrNoRows):
			row = nil
		case database.IsBusy(err):
			return nil, err
		default:
			// An unreadable row is an absent signal; status.json may still
			// answer, and if it does not, the error below names this one.
			row = nil
			if r.dbErr == nil {
				r.dbErr = err
			}
		}
	}
	statusPath := runner.SessionStatusPath(r.sessionsDir, uuid)
	file, fileErr := runner.ReadSessionStatus(statusPath)
	if fileErr != nil {
		file = nil
	}
	if row == nil && file == nil {
		if r.dbErr != nil {
			return nil, fmt.Errorf("no scan %s: database unavailable (%w) and no %s", uuid, r.dbErr, terminal.ShortenHome(statusPath))
		}
		return nil, codedErrorf(apicontract.CodeNotFound, "no scan found for uuid %s (checked the database and %s)", uuid, terminal.ShortenHome(statusPath))
	}

	var lastLog time.Time
	if row != nil && row.Status == "running" && r.repo != nil {
		lastLog = lastScanLogTimes(ctx, r.repo, []*database.Scan{row})[uuid]
	}
	logFile := resolveSessionLogPath(filepath.Join(r.sessionsDir, uuid))
	lv := sessionLiveness(row, statusPath, logFile, lastLog)

	view := buildScanStatusView(uuid, row, file, lv, livenessNow())
	if row != nil {
		view.DBPath = r.dbPath
		if r.repo != nil {
			if total, bySev, err := r.repo.ScanFindingTotal(ctx, uuid); err == nil {
				view.Findings, view.FindingsBySeverity = total, bySev
			}
		}
	}
	return view, nil
}

// buildScanStatusView merges the row (authoritative when present) and
// status.json (the only source of live progress, and of everything for a scan
// whose row lives in another store). Pure, for tests.
func buildScanStatusView(uuid string, row *database.Scan, file *runner.SessionStatus, lv Liveness, now time.Time) *scanStatusView {
	v := &scanStatusView{
		ScanUUID:           uuid,
		PhasesDone:         []string{},
		FindingsBySeverity: map[string]int{},
		Source:             []string{},
		Liveness: scanLivenessView{
			LastWriteAt: formatLivenessTime(lv.LastWriteAt),
			Sources:     lv.Sources,
			ProcessGone: lv.ProcessGone,
		},
	}
	if v.Liveness.Sources == nil {
		v.Liveness.Sources = []string{}
	}

	errorMessage := ""
	if row != nil {
		v.Source = append(v.Source, "db")
		v.Status = row.Status
		errorMessage = row.ErrorMessage
		v.ErrorMessage = row.ErrorMessage
		v.Phase = row.CurrentPhase
		v.RequestsSent = row.TotalRequests
		v.Completeness = row.Completeness
		v.StopReason = row.StopReason
		v.startedAt = row.StartedAt
		v.PID, v.RunnerHost = row.PID, row.RunnerHost
		v.ProjectUUID = row.ProjectUUID
		v.Findings = int(row.TotalFindings)
		for _, p := range row.PhaseOutcomes {
			if p.Phase != "" && p.Phase != string(runner.PhasePreflight) {
				v.PhasesDone = append(v.PhasesDone, p.Phase)
			}
		}
		if !row.FinishedAt.IsZero() {
			v.FinishedAt = formatLivenessTime(row.FinishedAt)
		}
	}
	if file != nil {
		v.Source = append(v.Source, "status_file")
		if row == nil {
			v.Status = file.Status
			v.startedAt = file.StartedAt
			v.PID, v.RunnerHost = file.PID, file.Host
			v.ProjectUUID = file.ProjectUUID
			v.DBPath = file.DBPath
			v.Findings = int(file.Findings)
			for sev, n := range file.FindingsBySeverity {
				v.FindingsBySeverity[sev] = int(n)
			}
		}
		if file.RequestsSent > v.RequestsSent {
			v.RequestsSent = file.RequestsSent
		}
		v.PhasesPlanned = file.PhasesPlanned
		v.budgetMS = file.ScanMaxDurationMS
		// Live facts only while the file itself says running: a finished
		// scan's last phase is history, not "the phase it is in".
		if file.Status == runner.SessionRunning {
			if file.Phase != "" {
				v.Phase = file.Phase
			}
			if file.PhaseStartedAt != nil {
				v.phaseStarted = *file.PhaseStartedAt
				v.PhaseStartedAt = formatLivenessTime(*file.PhaseStartedAt)
			}
			if file.Progress != nil && v.Phase == file.Phase {
				v.Progress = &scanProgressView{Done: file.Progress.Done, Total: file.Progress.Total, Unit: file.Progress.Unit}
			}
		}
		if len(v.PhasesDone) == 0 && len(file.PhasesDone) > 0 {
			v.PhasesDone = append(v.PhasesDone, file.PhasesDone...)
		}
	}

	v.EffectiveStatus = effectiveStatus(v.Status, errorMessage, lv)
	v.Liveness.Stale = v.Status == "running" && lv.Stale
	if v.EffectiveStatus != effStatusRunning {
		// Not running (anymore): no current phase or progress to report.
		v.Phase, v.PhaseStartedAt, v.Progress = "", nil, nil
	}

	if !v.startedAt.IsZero() {
		v.StartedAt = formatLivenessTime(v.startedAt)
	}
	switch {
	case row != nil && row.DurationMs > 0 && v.Status != "running":
		v.DurationMS = row.DurationMs
	case !v.startedAt.IsZero():
		end := now
		if v.EffectiveStatus == effStatusAbandoned && !lv.LastWriteAt.IsZero() {
			end = lv.LastWriteAt
		}
		if d := end.Sub(v.startedAt).Milliseconds(); d > 0 {
			v.DurationMS = d
		}
	}
	v.ETA = scanETA(v, now)
	return v
}

// etaRemainingPhasesFactor discounts the remaining phases' budget when it is
// folded into an estimate: phases routinely finish well inside their ceilings.
const etaRemainingPhasesFactor = 0.6

// scanETA computes the remaining-time estimate from what the view can prove.
//
//   - upper_bound_ms: the remaining --scanning-max-duration budget, the one
//     ceiling the whole scan obeys.
//   - estimate_ms: the current phase's own rate, elapsed × (total−done)/done,
//     when its total is known and it is the last planned phase. With phases
//     still to come there is no honest per-phase figure for them (the resolved
//     plan is not persisted yet), so the estimate stays null rather than
//     reporting the current phase's tail as the scan's.
//
// Clamped by the upper bound when both exist. Terminal scans report 0/0.
func scanETA(v *scanStatusView, now time.Time) scanETAView {
	if isTerminalEffectiveStatus(v.EffectiveStatus) {
		zero := int64(0)
		return scanETAView{EstimateMS: &zero, UpperBoundMS: &zero, Basis: "finished"}
	}
	eta := scanETAView{Basis: "unknown"}
	if v.EffectiveStatus != effStatusRunning {
		return eta
	}
	var bases []string

	if p := v.Progress; p != nil && p.Total != nil && p.Done > 0 && !v.phaseStarted.IsZero() && isLastPlannedPhase(v.Phase, v.PhasesPlanned) {
		elapsed := now.Sub(v.phaseStarted).Milliseconds()
		remaining := *p.Total - p.Done
		if elapsed > 0 && remaining >= 0 {
			est := int64(float64(elapsed) * float64(remaining) / float64(p.Done))
			eta.EstimateMS = &est
			bases = append(bases, "phase_rate")
		}
	}
	if v.budgetMS > 0 && !v.startedAt.IsZero() {
		left := v.budgetMS - now.Sub(v.startedAt).Milliseconds()
		if left < 0 {
			left = 0
		}
		eta.UpperBoundMS = &left
		bases = append(bases, "scan_budget")
	}
	if eta.EstimateMS != nil && eta.UpperBoundMS != nil && *eta.EstimateMS > *eta.UpperBoundMS {
		clamped := *eta.UpperBoundMS
		eta.EstimateMS = &clamped
	}
	if len(bases) > 0 {
		eta.Basis = strings.Join(bases, "+")
	}
	return eta
}

// isLastPlannedPhase reports whether phase is the final enabled phase of the
// plan. An unknown plan is not "last": the estimate then has no basis.
func isLastPlannedPhase(phase string, planned []string) bool {
	return phase != "" && len(planned) > 0 && planned[len(planned)-1] == phase
}

// printScanStatusHuman renders the view as an aligned key/value block.
func printScanStatusHuman(w *os.File, v *scanStatusView) {
	row := func(k, val string) {
		fmt.Fprintf(w, "  %s %s\n", terminal.Gray(fmt.Sprintf("%-14s", k)), val)
	}
	status := colorRunStatus(v.EffectiveStatus)
	if v.EffectiveStatus != v.Status && v.Status != "" {
		status += terminal.Gray(" (stored: " + v.Status + ")")
	}
	fmt.Fprintf(w, "%s %s\n", terminal.InfoSymbol(), terminal.BoldCyan(v.ScanUUID))
	row("status", status)
	if v.Phase != "" {
		row("phase", v.Phase)
	}
	if len(v.PhasesDone) > 0 {
		row("phases done", strings.Join(v.PhasesDone, ", "))
	}
	if p := v.Progress; p != nil {
		total := "?"
		if p.Total != nil {
			total = fmt.Sprintf("%d", *p.Total)
		}
		row("progress", fmt.Sprintf("%d/%s %s", p.Done, total, p.Unit))
	}
	row("requests", fmt.Sprintf("%d", v.RequestsSent))
	row("findings", formatStatusSeverityCounts(v.Findings, v.FindingsBySeverity))
	if v.Completeness != "" {
		c := v.Completeness
		if v.StopReason != "" {
			c += " (" + v.StopReason + ")"
		}
		row("completeness", c)
	}
	row("duration", fmtStatusDuration(v.DurationMS))
	row("eta", formatETA(v.ETA))
	last := "never"
	if v.Liveness.LastWriteAt != nil {
		last = *v.Liveness.LastWriteAt
	}
	row("last write", fmt.Sprintf("%s %s", last, terminal.Gray("("+strings.Join(v.Liveness.Sources, ", ")+")")))
	if v.ErrorMessage != "" && v.EffectiveStatus == effStatusFailed {
		row("error", v.ErrorMessage)
	}
}

func formatStatusSeverityCounts(total int, bySev map[string]int) string {
	if total == 0 {
		return "0"
	}
	var parts []string
	for i := len(severityOrder) - 1; i >= 0; i-- {
		if n := bySev[severityOrder[i]]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", severityOrder[i], n))
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%d", total)
	}
	return fmt.Sprintf("%d (%s)", total, strings.Join(parts, ", "))
}

func fmtStatusDuration(ms int64) string {
	return (time.Duration(ms) * time.Millisecond).Round(time.Second).String()
}

func formatETA(e scanETAView) string {
	switch {
	case e.Basis == "finished":
		return "done"
	case e.EstimateMS != nil && e.UpperBoundMS != nil:
		return fmt.Sprintf("~%s (at most %s)", fmtStatusDuration(*e.EstimateMS), fmtStatusDuration(*e.UpperBoundMS))
	case e.EstimateMS != nil:
		return "~" + fmtStatusDuration(*e.EstimateMS)
	case e.UpperBoundMS != nil:
		return "at most " + fmtStatusDuration(*e.UpperBoundMS)
	}
	return "unknown"
}
