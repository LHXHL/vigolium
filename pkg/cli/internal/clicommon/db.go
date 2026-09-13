// Package clicommon holds shared, leaf-level helpers used across the vigolium
// CLI command tree: the database-connection cache, project resolution, the
// --watch loop, logger flushing, and display formatting. It is intentionally
// dependency-light (no imports back into pkg/cli) so command groups can be
// split into their own subpackages and still share this common ground.
package clicommon

import (
	"context"
	"errors"
	"fmt"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"go.uber.org/zap"
)

// dbConn is the process-wide cached database connection shared by every command.
var dbConn *database.DB

// GetDB returns the cached database connection, opening it on first use.
// configPath is the --config path (may be empty) and dbPath is the --db SQLite
// override (may be empty). When the database is not explicitly enabled it
// defaults to SQLite at the standard location.
// ReadOnlyRequested is set by the CLI before the first GetDB call when the
// command must not modify its source (--read-only). It is a package var rather
// than a GetDB parameter because GetDB is called from ~30 sites that would all
// have to thread a value none of them decides.
var ReadOnlyRequested bool

func GetDB(configPath, dbPath string) (*database.DB, error) {
	if dbConn != nil {
		return dbConn, nil
	}

	settings, err := config.LoadSettings(configPath)
	if err != nil {
		zap.L().Warn("Failed to load settings, using defaults", zap.Error(err))
		settings = config.DefaultSettings()
	}

	// If database is not explicitly enabled, default to SQLite
	if !settings.Database.Enabled && settings.Database.Driver == "" {
		settings.Database.Enabled = true
		settings.Database.Driver = "sqlite"
		settings.Database.SQLite.Path = "~/.vigolium/database-vgnm.sqlite"
	}

	// Override SQLite path if --db flag is set
	if dbPath != "" {
		settings.Database.Driver = "sqlite"
		settings.Database.SQLite.Path = dbPath
	}

	// Only meaningful for SQLite; Postgres read-only is a server-side grant.
	if ReadOnlyRequested && settings.Database.Driver == "sqlite" {
		settings.Database.SQLite.ReadOnly = true
	}

	db, err := database.NewDB(&settings.Database)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Bring the schema up to date on EVERY open, not only on the write commands
	// that used to call CreateSchema themselves.
	//
	// Without this, a database written by an older vigolium fails its first read
	// with a raw `no such column: r.surface_score` — the read commands
	// (traffic/finding/db ls/export) never migrated, so any column added since
	// that file was last written simply was not there. Opening is exactly when a
	// store should be made current, and the read path is the one most likely to
	// meet an old file.
	//
	// EnsureSchemaCurrent, not CreateSchema: it checks for staleness with
	// READ-only queries and issues DDL only when something is actually missing.
	// CreateSchema unconditionally would take SQLite's write lock on every open,
	// making any read command queue behind a concurrent scan for up to
	// busy_timeout (measured: 22s for a `traffic` listing).
	if schemaErr := db.EnsureSchemaCurrent(context.Background()); schemaErr != nil {
		// An outdated schema on a read-only handle is fatal: it cannot be
		// migrated, and every query that follows would fail on a missing column
		// with an error that names no remedy. Any other migration failure is
		// best-effort — the schema may already be usable — so it only warns.
		if errors.Is(schemaErr, database.ErrSchemaOutdated) {
			return nil, schemaErr
		}
		zap.L().Warn("Failed to bring database schema up to date", zap.Error(schemaErr))
	}

	dbConn = db
	openedDBPath = config.ExpandPath(settings.Database.SQLite.Path)
	if settings.Database.Driver != "sqlite" {
		openedDBPath = settings.Database.Driver
	}
	return db, nil
}

// openedDBPath records which database the cached connection actually opened.
//
// The open order is --db → $VIGOLIUM_DB_PATH → config → the built-in default,
// and that last rung is ONE SHARED FILE under a single default project — so a
// command that falls through to it is reading every target that ever landed
// there. That is a cross-engagement mixing hazard a consumer cannot detect from
// the outside, which is why the resolved path is reported in every -j envelope
// (and in scan.started): a driver can then assert the store it read rather than
// trusting that its pin survived a subprocess chain.
var openedDBPath string

// OpenedDBPath returns the resolved path of the database currently open, or ""
// before any open. For a non-SQLite driver it returns the driver name, since
// there is no single file to name.
func OpenedDBPath() string { return openedDBPath }

// SetOpenedDBPath overrides the recorded path. For tests that exercise what is
// reported about a read without opening a database to produce it.
func SetOpenedDBPath(path string) { openedDBPath = path }

// CloseDatabaseOnExit closes the cached connection if open. Safe to defer.
func CloseDatabaseOnExit() {
	if dbConn != nil {
		_ = dbConn.Close()
	}
}

// ResetDBCache closes and clears the cached connection. Used by `db clean`
// before deleting the underlying SQLite file.
func ResetDBCache() {
	if dbConn != nil {
		_ = dbConn.Close()
		dbConn = nil
	}
}

// SetDBCache replaces the cached connection. Used by `db clean` after it
// recreates the database with a fresh schema.
func SetDBCache(db *database.DB) {
	dbConn = db
}
