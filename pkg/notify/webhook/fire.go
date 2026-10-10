package webhook

import (
	"context"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"go.uber.org/zap"
)

// Webhook event values. scan.completed is the one receivers have always
// seen; the other two are additive, so a receiver filtering on the old value
// gets exactly what it got before.
const (
	EventScanCompleted = "scan.completed"
	EventScanFailed    = "scan.failed"
	EventScanCancelled = "scan.cancelled"
)

// Payload status values for the non-row outcomes (a completed or failed
// native scan reports its row's status verbatim).
const statusCancelled = "cancelled"

// Outcome is what the firing caller knows about a run beyond its scan row. The
// row is authoritative whenever it holds a terminal status; Outcome decides
// only when the row is missing (the run failed before creating it) or never
// reached a terminal status. The fields after Interrupted fill the payload in
// that case.
type Outcome struct {
	// Err is the run's own failure (not an export failure); nil on success.
	Err error
	// Interrupted reports that a signal stopped the run.
	Interrupted bool

	ProjectUUID string
	Target      string
	StartedAt   time.Time
}

// FireNativeScan loads the native scan row and posts its terminal payload.
// No-op when settings are nil, the webhook is not enabled, or the outcome is
// filtered out by notify.webhook.events.
func FireNativeScan(settings *config.Settings, repo *database.Repository, scanUUID string) {
	FireNativeScanOutcome(settings, repo, scanUUID, Outcome{})
}

// FireNativeScanOutcome is FireNativeScan with the caller's view of the run,
// used when the row may be missing or unfinished (see Outcome). The payload is
// built synchronously — the row is read before this returns, so the caller may
// close or discard the database right after — and posted asynchronously.
func FireNativeScanOutcome(settings *config.Settings, repo *database.Repository, scanUUID string, out Outcome) {
	if settings == nil || scanUUID == "" {
		return
	}
	if !settings.Notify.IsWebhookActive() {
		return
	}
	sender := NewSender(settings.Notify.Webhook)
	if sender == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var scan *database.Scan
	if repo != nil {
		row, err := repo.GetScanByUUID(ctx, scanUUID)
		if err != nil {
			zap.L().Debug("[Notify] webhook: native scan not found", zap.String("scan_uuid", scanUUID), zap.Error(err))
		} else {
			scan = row
		}
	}
	payload, ok := NativeScanPayload(scanUUID, scan, out)
	if !ok {
		zap.L().Debug("[Notify] webhook: no scan row and no outcome to report", zap.String("scan_uuid", scanUUID))
		return
	}
	if !settings.Notify.Webhook.AllowsEvent(payload.Event) {
		zap.L().Debug("[Notify] webhook: event filtered by notify.webhook.events",
			zap.String("scan_uuid", scanUUID), zap.String("event", payload.Event))
		return
	}
	sender.PostAsync(payload)
}

// NativeScanPayload builds the payload for one native scan from its row (nil
// when it does not exist) and the caller's Outcome. ok is false when there is
// nothing to report: no row, and an Outcome that names neither a failure nor
// an interrupt.
func NativeScanPayload(scanUUID string, scan *database.Scan, out Outcome) (ScanCompletedPayload, bool) {
	if scan == nil {
		event, status, errMsg, known := outcomeEvent(out)
		if !known {
			return ScanCompletedPayload{}, false
		}
		started := out.StartedAt
		if started.IsZero() {
			started = time.Now()
		}
		return ScanCompletedPayload{
			Event:        event,
			ProjectUUID:  out.ProjectUUID,
			ScanUUID:     scanUUID,
			ScanType:     "native",
			Target:       out.Target,
			Status:       status,
			Completeness: database.CompletenessPartial,
			StopReason:   stopReasonFor(event),
			Error:        errMsg,
			StartedAt:    started,
			FinishedAt:   time.Now(),
			Findings:     FindingCounts{BySeverity: zeroSeverityCounts()},
		}, true
	}

	event, status, terminal := NativeEvent(scan.Status, scan.ErrorMessage, scan.StopReason)
	errMsg := ""
	if event == EventScanFailed {
		errMsg = scan.ErrorMessage
	}
	if !terminal {
		// The row never reached a terminal status. The caller's view decides
		// when it has one; otherwise report the row as it stands, the way this
		// hook always has.
		if e, st, msg, known := outcomeEvent(out); known {
			event, status, errMsg = e, st, msg
		}
	}
	finishedAt := scan.FinishedAt
	if finishedAt.IsZero() {
		finishedAt = time.Now()
	}
	return ScanCompletedPayload{
		Event:        event,
		ProjectUUID:  scan.ProjectUUID,
		ScanUUID:     scan.UUID,
		ScanType:     "native",
		Target:       scan.Target,
		Status:       status,
		Completeness: scan.Completeness,
		StopReason:   scan.StopReason,
		Error:        errMsg,
		StartedAt:    scan.StartedAt,
		FinishedAt:   finishedAt,
		Findings: FindingCounts{
			Total: int(scan.TotalFindings),
			BySeverity: map[string]int{
				"critical": int(scan.CriticalCount),
				"high":     int(scan.HighCount),
				"medium":   int(scan.MediumCount),
				"low":      int(scan.LowCount),
				"info":     int(scan.InfoCount),
			},
		},
		ResultURL: scan.StorageURL,
	}, true
}

// NativeEvent maps a native scan row's status to the webhook event and the
// payload status. terminal is false for a status that is not an end state
// (running, pending), which is reported as scan.completed with the status
// verbatim — what the hook sent before it knew other events.
//
// A cancelled scan is stored as status "failed" with error_message
// "cancelled" (stop_reason cancelled); it is reported as scan.cancelled with
// status "cancelled". A curtailed scan is "completed" with completeness
// "partial" and stays scan.completed.
func NativeEvent(status, errMsg, stopReason string) (event, outStatus string, terminal bool) {
	switch status {
	case "", "completed":
		return EventScanCompleted, "completed", true
	case statusCancelled:
		return EventScanCancelled, statusCancelled, true
	case "failed":
		if errMsg == "cancelled" || stopReason == database.ReasonCancelled {
			return EventScanCancelled, statusCancelled, true
		}
		return EventScanFailed, "failed", true
	}
	return EventScanCompleted, status, false
}

// outcomeEvent is the event an Outcome alone implies; known is false when it
// names neither an interrupt nor a failure.
func outcomeEvent(out Outcome) (event, status, errMsg string, known bool) {
	switch {
	case out.Interrupted:
		return EventScanCancelled, statusCancelled, "", true
	case out.Err != nil:
		return EventScanFailed, "failed", out.Err.Error(), true
	}
	return "", "", "", false
}

func stopReasonFor(event string) string {
	switch event {
	case EventScanCancelled:
		return database.ReasonCancelled
	case EventScanFailed:
		return database.ReasonError
	}
	return ""
}

func zeroSeverityCounts() map[string]int {
	return map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
}

// FireAgenticScan loads the agentic scan row, computes severity counts from
// associated findings, and posts a completion payload. No-op when
// settings/repo are nil or the webhook is not enabled.
func FireAgenticScan(settings *config.Settings, repo *database.Repository, agenticScanUUID string) {
	if settings == nil || repo == nil || agenticScanUUID == "" {
		return
	}
	if !settings.Notify.IsWebhookActive() {
		return
	}
	sender := NewSender(settings.Notify.Webhook)
	if sender == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	run, err := repo.GetAgenticScan(ctx, agenticScanUUID)
	if err != nil || run == nil {
		zap.L().Debug("[Notify] webhook: agentic scan not found", zap.String("agentic_scan_uuid", agenticScanUUID), zap.Error(err))
		return
	}

	bySeverity := agenticSeverityCounts(ctx, repo, agenticScanUUID)
	total := 0
	for _, n := range bySeverity {
		total += n
	}
	// AgenticScan.FindingCount is the source of truth when the run set it
	// explicitly (e.g. before findings rows landed); fall back to the
	// per-row aggregate otherwise.
	if total == 0 {
		total = run.FindingCount
	}

	scanType := strings.TrimSpace(run.Mode)
	if scanType == "" {
		scanType = "agentic"
	}
	status := run.Status
	if status == "" {
		status = "completed"
	}
	finishedAt := run.CompletedAt
	if finishedAt.IsZero() {
		finishedAt = time.Now()
	}

	event, completeness, stopReason := AgenticEvent(status)
	payload := ScanCompletedPayload{
		Event:        event,
		ProjectUUID:  run.ProjectUUID,
		ScanUUID:     run.UUID,
		ScanType:     scanType,
		Target:       run.TargetURL,
		Status:       status,
		Completeness: completeness,
		StopReason:   stopReason,
		StartedAt:    run.StartedAt,
		FinishedAt:   finishedAt,
		Findings: FindingCounts{
			Total:      total,
			BySeverity: bySeverity,
		},
		ResultURL: run.StorageURL,
	}
	if event == EventScanFailed {
		payload.Error = run.ErrorMessage
	}
	if !settings.Notify.Webhook.AllowsEvent(payload.Event) {
		zap.L().Debug("[Notify] webhook: event filtered by notify.webhook.events",
			zap.String("agentic_scan_uuid", agenticScanUUID), zap.String("event", payload.Event))
		return
	}
	sender.PostAsync(payload)
}

// AgenticEvent maps an agentic run's status to the webhook event. The status
// itself is reported verbatim. A run that stopped at its time or budget limit
// ran, so it is scan.completed with completeness "partial" and the limit as
// stop_reason — the same shape as a curtailed native scan. A status outside
// the terminal set is scan.completed, as the hook always reported it.
func AgenticEvent(status string) (event, completeness, stopReason string) {
	switch status {
	case "cancelled":
		return EventScanCancelled, database.CompletenessPartial, database.ReasonCancelled
	case "failed", "error":
		return EventScanFailed, database.CompletenessPartial, database.ReasonError
	case "timeout", "budget_exhausted":
		return EventScanCompleted, database.CompletenessPartial, status
	}
	return EventScanCompleted, "", ""
}

// agenticSeverityCounts returns finding counts grouped by severity for one
// agentic scan, with canonical severity keys (critical/high/medium/low/info)
// always present (zero if absent) so downstream JSON payload shape stays
// stable. Unknown severities are preserved verbatim.
func agenticSeverityCounts(ctx context.Context, repo *database.Repository, agenticScanUUID string) map[string]int {
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	rows, err := database.CountFindingsByAgenticScan(ctx, repo.DB(), agenticScanUUID)
	if err != nil {
		zap.L().Debug("[Notify] webhook: severity aggregation failed", zap.String("agentic_scan_uuid", agenticScanUUID), zap.Error(err))
		return counts
	}
	for key, n := range rows {
		counts[key] = int(n)
	}
	return counts
}
