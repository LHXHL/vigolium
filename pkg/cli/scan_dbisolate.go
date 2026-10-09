package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/vigolium/vigolium/internal/scratch"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// dbIsolateAgentFlagUsage is the shared --db-isolate help text for the agent
// subcommands (autopilot, swarm). scan/run use a variant that also references
// --stateless, so it keeps its own string.
const dbIsolateAgentFlagUsage = "Run into a private temporary database, then merge results into --db (or the default DB) at the end — lets parallel runs share one --db without write contention (SQLite only)"

// dbIsolateYieldsToStateless applies the precedence between --db-isolate and
// --stateless: -S wins and --db-isolate is ignored with a warning.
//
// The pair used to be a hard error. It is a warning because tools that compose
// vigolium's flags pass both, and refusing to start stops a whole workflow over
// a flag that simply has nothing to do: -S discards the run's database, so there
// is no database left to merge anywhere. Which side wins is not arbitrary:
// were --db-isolate to win, a run that asked for -S would begin merging into the
// operator's project DB, the one thing -S promises will not happen.
//
// The flag is dropped outright rather than half-honored, so every remaining
// combination validates exactly as if it had never been typed: -S --db-isolate
// --db still reports the --db conflict, and -S --db-isolate -P still meets the
// -P isolation gate (which asks for --split-by-host). Anything softer would make
// adding an ignored flag *widen* what the CLI accepts.
//
// It clears globalDBIsolate rather than reporting the conflict, because the flag
// var IS the flag: dbIsolateBegin reads it directly (not an Options field), and
// by the time that runs the stateless path has already repointed
// settings.Database/globalDB at its throwaway file — a stale flag there would
// merge a second scratch database into one that is about to be deleted. Callers
// that copy the flag into Options must therefore copy it AFTER this runs.
func dbIsolateYieldsToStateless(stateless bool) {
	if !stateless || !globalDBIsolate {
		return
	}
	if !machineOutputMode() {
		fmt.Fprintf(os.Stderr,
			"%s %s is ignored under %s: this run's database is discarded, so there is nothing to merge into %s.\n",
			terminal.WarnPrefix(),
			terminal.BoldCyan("--db-isolate"),
			terminal.BoldCyan("--stateless"),
			terminal.BoldCyan("--db"))
	}
	globalDBIsolate = false
}

// dbIsolateDestPath records the real destination database that a --db-isolate
// run merges into at the end. dbIsolateBegin repoints settings.Database and
// globalDB at the scratch file, which erases the original destination from
// those, so we stash it here for the config banner (printScanSummary) to show.
var dbIsolateDestPath string

// resolveDBIsolateDest resolves the real destination database a --db-isolate run
// merges into: the global --db when set, otherwise the configured database. It
// errors when that destination is not SQLite (the merge is SQLite-to-SQLite).
// Shared by dbIsolateBegin (single-process runs) and the db-isolate parallel
// fan-out, which needs the destination both to validate up front and to export
// the unified output from once every child has merged in.
func resolveDBIsolateDest(settings *config.Settings) (config.DatabaseConfig, error) {
	destCfg := settings.Database
	if globalDB != "" {
		destCfg.Driver = "sqlite"
		destCfg.SQLite.Path = globalDB
	}
	if destCfg.Driver != "sqlite" {
		return destCfg, usageErrorf("--db-isolate requires a SQLite database (got driver %q)", destCfg.Driver)
	}
	return destCfg, nil
}

// dbIsolateBegin, when --db-isolate is active, swaps the run's database to a
// private scratch SQLite file and returns a finisher that merges the scratch
// into the real destination (--db when set, else the configured DB) and cleans
// it up. It repoints BOTH database-acquisition paths at the scratch:
// settings.Database (native scan and swarm via NewDB) and the global --db value
// (autopilot via getDB → clicommon.GetDB). When isolation is off it returns a
// no-op finisher, so callers can unconditionally `defer finish(err)`.
//
// Shared by `scan`/`run`, `agent autopilot`, and `agent swarm`; register the
// returned finisher in a defer BEFORE opening the DB so the merge runs after
// the DB is closed (defers are LIFO).
func dbIsolateBegin(settings *config.Settings, silent bool) (finish func(error) error, err error) {
	noop := func(runErr error) error { return runErr }
	if !globalDBIsolate {
		return noop, nil
	}
	// Resolve the real destination: --db wins, else the configured DB.
	destCfg, err := resolveDBIsolateDest(settings)
	if err != nil {
		return nil, err
	}
	// Stash the destination before we repoint settings/globalDB below, so the
	// config banner can report where results will be merged.
	dbIsolateDestPath = destCfg.SQLite.Path

	tmpFile, tmpErr := scratch.CreateTemp("isolate-*.sqlite")
	if tmpErr != nil {
		return nil, fmt.Errorf("failed to create temporary database: %w", tmpErr)
	}
	scratchPath := tmpFile.Name()
	_ = tmpFile.Close()

	settings.Database.Driver = "sqlite"
	settings.Database.SQLite.Path = scratchPath
	// autopilot opens via getDB() → clicommon.GetDB(globalConfig, globalDB),
	// which ignores settings.Database, so the scratch path must be reflected in
	// globalDB too. Harmless for the native/swarm paths (they read settings).
	globalDB = scratchPath

	return func(runErr error) error {
		return finishDBIsolateMerge(destCfg, scratchPath, silent, runErr)
	}, nil
}

// finishDBIsolateMerge merges the scratch database produced by a --db-isolate
// run into the real destination database, then discards the scratch on
// success. It is called from a defer that runs after the run's DB handle is
// closed, so the scratch DB's writes are fully flushed before the merge reads
// them. scanErr is the run's own error (if any): on a clean merge it is
// returned unchanged; on a merge failure the scratch is preserved and the
// command still exits non-zero.
func finishDBIsolateMerge(destCfg config.DatabaseConfig, scratchPath string, silent bool, scanErr error) error {
	ctx := context.Background()
	destPath := database.ExpandPath(destCfg.SQLite.Path)

	// Serialize the ENTIRE destination-DB critical section — open, schema
	// creation, default seeding, and the merge — under one cross-process lock.
	// When many --db-isolate finishers target a single fresh shared --db (the
	// -P fan-out and parallel-process case), opening the DB runs a WAL-mode
	// switch + initial checkpoint and CreateSchema runs a batch of
	// CREATE TABLE/INDEX IF NOT EXISTS DDL — all write operations that, outside
	// the lock, run with no busy-retry of their own and can surface SQLITE_BUSY
	// under heavy concurrent load, failing the merge. Holding the lock across
	// open→schema→seed→merge means only one process initializes/writes the
	// shared destination at a time; the rest see an already-initialized DB and
	// their IF NOT EXISTS DDL is a fast no-op. The lock stays best-effort (it
	// degrades to DB-level serialization on timeout), and MergeSQLiteFile keeps
	// its own busy-retry for that degraded path.
	var stats *database.MergeStats
	mergeErr := database.WithMergeLock(destPath, 60*time.Second, func() error {
		dest, err := database.NewDB(&destCfg)
		if err != nil {
			return fmt.Errorf("open destination database: %w", err)
		}
		defer func() { _ = dest.Close() }()

		if err := dest.CreateSchema(ctx); err != nil {
			return fmt.Errorf("prepare destination schema: %w", err)
		}
		// Best-effort: seed the default project/FTS so a brand-new destination is
		// fully usable; a failure here doesn't block the merge of the result rows.
		_ = dest.SeedDefaults(ctx)

		var e error
		stats, e = database.MergeSQLiteFile(ctx, dest, scratchPath)
		return e
	})
	if mergeErr != nil {
		return dbIsolateMergeFailed(scratchPath, scanErr, mergeErr)
	}

	// Success: discard the scratch database and its WAL sidecars.
	removeWorkingDB(scratchPath)
	if !silent && stats != nil {
		fmt.Fprintf(os.Stderr, "%s Merged results into %s (%d records, %d findings)\n",
			terminal.InfoSymbol(), terminal.Cyan(destCfg.SQLite.Path), stats.RecordsMerged, stats.FindingsMerged)
	}
	return scanErr
}

// dbIsolateMergeFailed moves the scratch database somewhere that outlives the
// process, prints a recovery hint naming that path, and returns the error the
// command should exit with: the original scan error when the scan itself
// failed, otherwise the merge error.
//
// The move is the fix for a false promise. This used to print "This scan's
// results are preserved in the temporary database: <scratch path>" — and that
// path is inside the process scratch directory, which releaseScratch removes at
// exit, moments later. The operator was told where to find results that were
// already being deleted. The word "preserved" is now never printed next to a
// scratch path: either the file has been moved out, or the message says it could
// not be.
func dbIsolateMergeFailed(scratchPath string, scanErr, mergeErr error) error {
	fmt.Fprintf(os.Stderr, "%s --db-isolate merge failed: %v\n", terminal.ErrorPrefix(), mergeErr)

	dest, keepErr := preserveWorkingDB(scratchPath, "isolate")
	if keepErr != nil {
		fmt.Fprintf(os.Stderr, "   This scan's results could NOT be preserved: %v\n", keepErr)
		zap.L().Error("db-isolate merge failed and the scratch database could not be preserved",
			zap.String("scratch", scratchPath), zap.Error(mergeErr), zap.NamedError("preserve_error", keepErr))
		if scanErr != nil {
			return scanErr
		}
		// keepErr's text, not keepErr itself: it is an os error that may wrap
		// os.ErrNotExist, and adding that to the chain would make the error
		// classify as source_missing — telling a driver the database it had just
		// been scanning is not there. mergeErr is the cause worth classifying.
		return fmt.Errorf("db-isolate merge failed (results lost: %s): %w", keepErr.Error(), mergeErr)
	}

	fmt.Fprintf(os.Stderr,
		"   This scan's results are preserved at:\n     %s\n   Merge them later with: %s\n",
		terminal.Cyan(dest),
		terminal.BoldCyan(fmt.Sprintf("vigolium import --db %s %s", dbIsolateDestPath, dest)))
	zap.L().Error("db-isolate merge failed; working database preserved",
		zap.String("scratch", scratchPath), zap.String("preserved", dest), zap.Error(mergeErr))

	if scanErr != nil {
		return fmt.Errorf("%w (db-isolate results kept at %s)", scanErr, dest)
	}
	return fmt.Errorf("db-isolate merge failed (results kept at %s): %w", dest, mergeErr)
}
