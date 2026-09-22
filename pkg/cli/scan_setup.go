package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/vigolium/vigolium/internal/config"
)

// Setup timing, kept separate from the scan's own budget.
//
// Schema readiness used to run on context.Background(), with no deadline at all
// — the runner's --scanning-max-duration budget does not exist yet at that
// point. That is not a theoretical gap: establishing readiness on a store
// another process is writing can sit on SQLite's busy_timeout, and an unbounded
// wait there is indistinguishable from a hung scan while spending the
// wall-clock the operator budgeted for scanning.
//
// So setup gets its own deadline, derived from the wait it is actually allowed
// to do (busy_timeout) rather than from the scan budget, and an expiry names the
// step that ran out of time.
//
// Scope, so the next reader does not assume more than this covers: it bounds the
// readiness QUESTION only. EnsureSchemaReady deliberately runs the repair
// without the deadline (its doc says why), and database.NewDB takes no context
// at all, so the open itself — sql.Open, Ping, and the pragmas Ping applies —
// remains unbounded. Bounding that needs NewDB(ctx, cfg) and ~30 call sites.

// setupGraceFactor multiplies the configured busy_timeout to get the setup
// deadline. Comfortably more than one full lock wait, so a database that
// genuinely owes migrations still gets to finish them behind another writer,
// while an indefinite stall is still bounded.
const setupGraceFactor = 3

// minSetupTimeout floors the setup deadline for configurations with a small or
// zero busy_timeout, where a proportional deadline would be tighter than the
// schema work itself.
const minSetupTimeout = 30 * time.Second

// setupContext returns the context for pre-runner setup steps, bounded so a
// contended or unresponsive store cannot stall startup indefinitely.
//
// Deliberately NOT a signal.NotifyContext: installing a SIGINT handler here
// would stop Go's default "interrupt terminates the process" behavior for the
// whole window before the runner installs its own graceful handler, turning an
// unresponsive setup into an uninterruptible one. Default SIGINT handling is the
// better answer until there is a runner to shut down gracefully.
func setupContext(settings *config.Settings) (context.Context, context.CancelFunc) {
	timeout := minSetupTimeout
	if settings != nil {
		busy := time.Duration(settings.Database.SQLite.BusyTimeout) * time.Millisecond
		timeout = max(timeout, busy*setupGraceFactor)
	}
	return context.WithTimeout(context.Background(), timeout)
}

// wrapSetupError annotates a failed setup step, naming the step and — when the
// setup deadline is what ended it — the contention that is the likely cause,
// since "failed to create database schema: context deadline exceeded" names
// neither the wait nor what to do about it.
//
// The remedy depends on the driver: --db-isolate is SQLite-only (see
// resolveDBIsolateDest, which refuses any other driver), so suggesting it to a
// Postgres deployment would point at a flag that cannot run.
func wrapSetupError(ctx context.Context, driver, step string, err error) error {
	if err == nil {
		return nil
	}
	if !isWallTimeout(ctx, err) {
		return fmt.Errorf("%s failed: %w", step, err)
	}
	remedy := "another session may be holding a conflicting lock on the database; " +
		"retry, or use --stateless to scan into a throwaway store"
	if driver == "sqlite" {
		remedy = "another process may be holding the database write lock " +
			"(check for a running `vigolium serve` or a concurrent scan), " +
			"or use --stateless / --db-isolate"
	}
	return fmt.Errorf("%s timed out; %s: %w", step, remedy, err)
}
