package cli

import (
	"context"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/types"
)

// beginScanEventStream installs the process event emitter for this scan and
// writes the opening scan.started line. It returns a finish func that emits the
// terminal scan.finished — call it (deferred) on every exit path.
//
// The emitter is installed AFTER the scan uuid is pinned and the DB is open, so
// scan.started can carry the two facts a consumer most needs to attribute later
// events: which scan row this is, and which database it landed in. Everything
// before that point is setup that fails loudly on its own.
func beginScanEventStream(db *database.DB, opts *types.Options, settings *config.Settings, strategyName string, start time.Time) (finish func(error), err error) {
	format, err := scanevents.ParseFormat(opts.Events)
	if err != nil {
		return nil, err
	}
	if format == "" {
		return func(error) {}, nil
	}

	emitter := scanevents.NewStdout(opts.ScanUUID)
	scanevents.Install(emitter)

	globalPace, phasePace := resolvedPaceTable(settings, opts)
	target := ""
	if len(opts.Targets) == 1 {
		target = opts.Targets[0]
	}

	dbPath := ""
	if settings != nil && settings.Database.Driver == "sqlite" {
		dbPath = config.ExpandPath(settings.Database.SQLite.Path)
	}

	scanevents.Emit(scanevents.Event{
		Type:      scanevents.TypeScanStarted,
		Target:    target,
		Targets:   len(opts.Targets),
		Strategy:  strategyName,
		Phases:    plannedPhaseIDs(opts),
		DBPath:    dbPath,
		Project:   opts.ProjectUUID,
		Pace:      &globalPace,
		PhasePace: phasePace,
	})

	// SIGINT/SIGTERM must still produce a terminal event: the absence of one is
	// how a consumer detects a SIGKILL, and that only works if every signal we
	// CAN catch produces one.
	stopSignals := scanevents.TrapSignals(start)

	return func(runErr error) {
		stopSignals()
		ev := scanevents.Event{
			Status:     scanevents.StatusCompleted,
			DurationMS: time.Since(start).Milliseconds(),
		}
		if runErr != nil {
			ev.Status = scanevents.StatusFailed
			ev.Message = runErr.Error()
		}
		scanFinishTotals(db, &ev, opts)
		scanevents.Finish(ev)
	}, nil
}

// scanFinishTotals fills the terminal event's tallies from the database the scan
// wrote. Read here rather than accumulated during the run because the accurate
// number is the persisted one: findings are deduped and grouped on their way in,
// so a live counter of emitted results overstates what a consumer will actually
// find when it queries.
func scanFinishTotals(db *database.DB, ev *scanevents.Event, opts *types.Options) {
	if db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	repo := database.NewRepository(db)
	if counts := repo.ScanSeverityTally(ctx, opts.ScanUUID); len(counts) > 0 {
		ev.FindingsBySeverity = counts
	}
	if n, err := repo.CountRecordsForScan(ctx, opts.ProjectUUID, opts.ScanUUID); err == nil {
		ev.RecordsWritten = scanevents.Int64(n)
	}
}

// plannedPhaseIDs returns the CANONICAL ids of the phases this scan will run, in
// execution order. Canonical, because --only/--skip and `vigolium run <phase>`
// all accept aliases (kis, cve, deparos, dast, …) and a consumer that asked for
// one spelling needs to be able to assert what it actually got.
func plannedPhaseIDs(opts *types.Options) []string {
	plan := runner.BuildNativeScanPlan(opts)
	out := make([]string, 0, len(plan.Steps))
	for _, step := range plan.Steps {
		if step.Enabled {
			out = append(out, string(step.Phase))
		}
	}
	return out
}

// validateEventsFlag rejects an --events value up front, before any scanning
// work, so a typo fails in milliseconds instead of after a 15-minute crawl and
// a scan whose whole reason for running was the stream it never produced.
func validateEventsFlag(value string) error {
	_, err := scanevents.ParseFormat(value)
	return err
}
