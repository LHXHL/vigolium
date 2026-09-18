package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/pgdriver"
	"github.com/uptrace/bun/driver/sqliteshim"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/utils"
	"go.uber.org/zap"
)

// envSQLTrace opts into per-statement SQL logging on top of --debug. Named here
// rather than inlined so it is greppable — it is the only way to reach the hook.
const envSQLTrace = "VIGOLIUM_SQL_TRACE"

// driverPostgres / driverSQLite are the values DB.driver takes. Named so the
// driver-conditional branches (timestamp precision, DDL adaptation, upserts)
// are greppable rather than scattered string literals.
const (
	driverPostgres = "postgres"
	driverSQLite   = "sqlite"
)

// DB wraps bun.DB with additional metadata
type DB struct {
	*bun.DB
	driver string

	// Full-text search capability, discovered on first use rather than assumed
	// from how this handle was opened. See HasFTS.
	ftsMu    sync.Mutex
	ftsKnown bool
	hasFTS   bool // true if FTS5 (SQLite) or tsvector (Postgres) is available

	// ckptStop stops the background WAL checkpointer (file-backed SQLite only;
	// nil otherwise). Closed once by Close().
	ckptStop     chan struct{}
	ckptStopOnce sync.Once

	// readOnly is set when the handle was opened with SQLiteConfig.ReadOnly. It
	// makes CreateSchema a no-op: a read-only source cannot be migrated, and the
	// read commands call CreateSchema unconditionally on open.
	readOnly bool

	// ownedSidecars names the database whose -wal/-shm files this read-only open
	// brought into existence; Close removes them again. Empty when there is
	// nothing to reclaim. See reclaimSidecars.
	ownedSidecars string

	// path is the resolved SQLite file this handle opened, empty for Postgres and
	// ":memory:" for an in-memory store. Reported by Path().
	path string

	// deferRecordIndexes postpones the http_records read indexes past CreateSchema
	// so a bulk load does not maintain them per row. See DeferRecordIndexes.
	deferRecordIndexes bool
}

// SQLite WAL tuning. wal_autocheckpoint runs an automatic PASSIVE checkpoint
// after this many WAL pages accumulate; mmap_size enables memory-mapped reads.
// These are applied per-connection via the DSN. The autocheckpoint alone can't
// reclaim the WAL while a reader pins old frames (the scan-on-receive poller,
// status-tick counts, and read API calls all hold read locks in a long-running
// server), so startWALCheckpointer also forces a TRUNCATE checkpoint on a timer.
const (
	sqliteWALAutocheckpoint = 1000      // pages (~4 MiB at 4 KiB/page)
	sqliteMmapSize          = 268435456 // 256 MiB
	walCheckpointInterval   = 5 * time.Minute
)

// NewDB creates database connection based on config
func NewDB(cfg *config.DatabaseConfig) (*DB, error) {
	if cfg == nil {
		return nil, fmt.Errorf("database config is nil")
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid database config: %w", err)
	}

	var sqldb *sql.DB
	var bunDB *bun.DB
	var driver string

	// Sampled BEFORE the open, so "this open made them" is a fact rather than a
	// guess. Only a read-only open can own sidecars: every other path checkpoints
	// and removes them itself on close.
	var ownedSidecarPath string
	if cfg.Driver == "sqlite" && cfg.SQLite.ReadOnly {
		if path := expandPath(cfg.SQLite.Path); !sidecarsPresent(path) {
			ownedSidecarPath = path
		}
	}

	switch cfg.Driver {
	case "sqlite":
		var err error
		sqldb, err = openSQLite(&cfg.SQLite)
		if err != nil {
			return nil, fmt.Errorf("failed to open SQLite: %w", err)
		}
		bunDB = bun.NewDB(sqldb, sqlitedialect.New())
		driver = "sqlite"

	case "postgres":
		var err error
		sqldb, err = openPostgres(&cfg.Postgres)
		if err != nil {
			return nil, fmt.Errorf("failed to open PostgreSQL: %w", err)
		}
		bunDB = bun.NewDB(sqldb, pgdialect.New())
		driver = "postgres"

	default:
		return nil, fmt.Errorf("unsupported database driver: %s", cfg.Driver)
	}

	db := &DB{
		DB:            bunDB,
		driver:        driver,
		readOnly:      driver == "sqlite" && cfg.SQLite.ReadOnly,
		ownedSidecars: ownedSidecarPath,
	}
	if driver == "sqlite" {
		db.path = expandPath(cfg.SQLite.Path)
	}

	// Per-statement SQL logging is opt-in on top of debug level, not implied by it.
	// A scan issues thousands of writes, so this hook is the bulk of --debug output
	// and formatting/emitting every statement is itself an observer effect on the
	// write path — which made --debug unusable for diagnosing anything else.
	// Set VIGOLIUM_SQL_TRACE=1 with --debug when you actually want query tracing.
	if zap.L().Core().Enabled(zap.DebugLevel) && utils.EnvTruthy(envSQLTrace) {
		db.AddQueryHook(debugQueryHook{})
	}

	// Periodically truncate the WAL for file-backed SQLite so it can't grow
	// without bound over a long-running process. No-op for Postgres and
	// in-memory SQLite (no WAL file). Stopped by Close().
	// Never on a read-only handle: the checkpointer's whole job is to rewrite the
	// WAL, which is exactly the mutation read-only mode exists to prevent.
	if driver == "sqlite" && !strings.Contains(cfg.SQLite.Path, ":memory:") && !cfg.SQLite.ReadOnly {
		db.startWALCheckpointer()
	}

	return db, nil
}

// startWALCheckpointer launches a background goroutine that forces a TRUNCATE
// WAL checkpoint every walCheckpointInterval, reclaiming WAL disk space that the
// automatic PASSIVE checkpoint can't while readers pin old frames. The ticker
// fires only in long-running processes (a short CLI scan exits before the first
// tick); the goroutine is stopped by Close().
func (db *DB) startWALCheckpointer() {
	db.ckptStop = make(chan struct{})
	stop := db.ckptStop
	go func() {
		ticker := time.NewTicker(walCheckpointInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				if _, err := db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
					zap.L().Debug("WAL checkpoint failed", zap.Error(err))
				}
				// Refresh planner stats on the same cadence so a long-running
				// server keeps good plans as the tables grow.
				db.Optimize(ctx)
				cancel()
			}
		}
	}()
}

// NewDBFromBun wraps an existing bun.DB for use in tests or external tooling.
func NewDBFromBun(bunDB *bun.DB, driver string) *DB {
	return &DB{DB: bunDB, driver: driver}
}

// openSQLiteReadOnly opens an existing SQLite file without modifying it.
//
// Three things are deliberately omitted relative to the read-write path, because
// each one is a write to the artifact:
//
//   - no os.MkdirAll — a missing file is an error, not a new database;
//   - no journal_mode PRAGMA — setting it rewrites the header, which is what
//     flipped evidence files from `delete` to `wal` and changed their hash;
//   - no startup wal_checkpoint(TRUNCATE) — that rewrites both the main file and
//     the -wal sidecar.
//
// `mode=ro` is the driver's own read-only mode; it still reads a pre-existing
// -wal sidecar, so a database another process left mid-WAL is read correctly
// rather than as a stale snapshot. `immutable=1` would be faster and is
// deliberately NOT used: it tells SQLite to assume the file cannot change, which
// silently returns wrong data if it does.
//
// What mode=ro does NOT avoid is the shared-memory index: reading a WAL-mode
// database requires a -shm, and SQLite creates one (and an empty -wal) when it
// is absent. So a --read-only pass over an evidence file left two new files
// beside it while an ordinary read left none — the read-write path creates the
// same sidecars but checkpoints and removes them on close. The returned
// `created` list is what Close reclaims to make the two paths symmetric; the
// main file was, and remains, byte-identical either way.
func openSQLiteReadOnly(path string, cfg *config.SQLiteConfig) (*sql.DB, error) {
	if path == ":memory:" {
		return nil, errors.New("read-only mode requires a file-backed database, not :memory: storage")
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("database file not readable: %w", err)
	}

	dsn := fmt.Sprintf(
		"file:%s?mode=ro&_pragma=busy_timeout(%d)&_pragma=query_only(1)&_pragma=cache_size(%d)&_pragma=temp_store(memory)&_pragma=mmap_size(%d)",
		path, cfg.BusyTimeout, cfg.CacheSize, sqliteMmapSize,
	)
	sqldb, err := sql.Open(sqliteshim.ShimName, dsn)
	if err != nil {
		return nil, err
	}
	if err := sqldb.Ping(); err != nil {
		_ = sqldb.Close()
		return nil, fmt.Errorf("failed to open database read-only: %w", err)
	}
	maxConns := cfg.MaxOpenConns
	if maxConns <= 0 {
		maxConns = 8
	}
	sqldb.SetMaxOpenConns(maxConns)
	sqldb.SetMaxIdleConns(maxConns)
	return sqldb, nil
}

// sidecarSuffixes are the files SQLite keeps beside a WAL-mode database.
var sidecarSuffixes = []string{"-wal", "-shm"}

// sidecarsPresent reports whether any sidecar already exists for path.
func sidecarsPresent(path string) bool {
	for _, suffix := range sidecarSuffixes {
		if _, err := os.Stat(path + suffix); err == nil {
			return true
		}
	}
	return false
}

// reclaimSidecars removes the -wal/-shm files this handle's open created,
// leaving the directory as it was found. Called from Close, after the sql.DB is
// closed so our own descriptors are gone.
//
// A non-empty -wal is left alone. This handle never wrote a frame — it was
// opened query_only — so frames there came from another process writing
// concurrently, and deleting that WAL would discard its committed transactions.
// Refusing is the whole safety argument: the only file this removes is one that
// is both ours and empty.
//
// Best-effort throughout. A removal that fails leaves a file that the next open
// will simply reuse, which is the pre-existing behavior and harms nothing.
func reclaimSidecars(path string) {
	if path == "" {
		return
	}
	if info, err := os.Stat(path + "-wal"); err == nil && info.Size() > 0 {
		return
	}
	for _, suffix := range sidecarSuffixes {
		_ = os.Remove(path + suffix)
	}
}

// openSQLite creates SQLite connection with optimized settings
func openSQLite(cfg *config.SQLiteConfig) (*sql.DB, error) {
	// Expand path (handle ~ and environment variables)
	path := expandPath(cfg.Path)

	// A read-only open must not bring the file (or its directory) into existence:
	// creating a parent for a path that was mistyped is how a read silently
	// becomes a new empty database instead of an error.
	if cfg.ReadOnly {
		return openSQLiteReadOnly(path, cfg)
	}

	// Ensure parent directory exists (skip for in-memory databases)
	if path != ":memory:" {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create database directory: %w", err)
		}
	}

	// Build DSN with PRAGMA settings.
	//
	// sqliteshim resolves to the pure-Go modernc.org/sqlite driver, which
	// expects connection PRAGMAs via repeated _pragma=<name>(<value>) query
	// params. The legacy mattn/go-sqlite3 form (_busy_timeout=, _journal_mode=)
	// is silently ignored by modernc, which left every connection on the
	// SQLite defaults: busy_timeout=0 and journal_mode=delete. Under
	// concurrent writers (e.g. RecordWriter batch flushes with
	// MaxOpenConns>1) that yields immediate SQLITE_BUSY failures because no
	// busy handler is installed and rollback-journal mode allows only one
	// writer. Emitting the modernc _pragma form actually applies busy_timeout
	// and WAL so writers serialize instead of failing.
	//
	// _txlock=immediate makes every transaction start with BEGIN IMMEDIATE so
	// it takes the write lock up front; combined with a real busy_timeout this
	// serializes concurrent writers rather than racing them. Both _pragma and
	// _txlock are honored by modernc; mattn (if ever selected) ignores the
	// unknown params and falls back to its own defaults harmlessly.
	// wal_autocheckpoint / temp_store / mmap_size are appended so each connection
	// keeps the WAL bounded, spills temp B-trees to memory, and uses mmap reads —
	// matching the deparos sitemap driver. Without wal_autocheckpoint the main
	// ingest DB ran on the SQLite default with no periodic reclaim path of its
	// own; the WAL could balloon to GB over a multi-day server run.
	dsn := fmt.Sprintf(
		"%s?_pragma=busy_timeout(%d)&_pragma=journal_mode(%s)&_pragma=synchronous(%s)&_pragma=cache_size(%d)&_pragma=wal_autocheckpoint(%d)&_pragma=temp_store(memory)&_pragma=mmap_size(%d)&_txlock=immediate",
		path,
		cfg.BusyTimeout,
		cfg.JournalMode,
		cfg.Synchronous,
		cfg.CacheSize,
		sqliteWALAutocheckpoint,
		sqliteMmapSize,
	)

	sqldb, err := sql.Open(sqliteshim.ShimName, dsn)
	if err != nil {
		return nil, err
	}

	// Test connection
	if err := sqldb.Ping(); err != nil {
		_ = sqldb.Close()
		return nil, fmt.Errorf("failed to ping SQLite: %w", err)
	}

	// Checkpoint + truncate any WAL left over from a previous run so the file
	// starts compact (no-op outside WAL mode; just-opened DB has no readers yet).
	if strings.EqualFold(cfg.JournalMode, "WAL") && path != ":memory:" {
		if _, err := sqldb.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
			zap.L().Debug("initial WAL checkpoint failed", zap.Error(err))
		}
	}

	// In WAL mode, SQLite supports concurrent readers alongside a single writer.
	// Default to 8 connections so the long-running server's readers (the
	// scan-on-receive poller, status-tick counts, and read API calls) don't
	// serialize behind a too-small pool; a slow read no longer ties up a quarter
	// of the connections. For in-memory databases (:memory:), force a single
	// connection since each connection gets its own isolated database — multiple
	// connections would cause "no such table" errors as schema created on one
	// connection is invisible to others.
	maxConns := cfg.MaxOpenConns
	if maxConns <= 0 {
		maxConns = 8
	}
	if path == ":memory:" {
		maxConns = 1
	}
	sqldb.SetMaxOpenConns(maxConns)
	sqldb.SetMaxIdleConns(maxConns)

	return sqldb, nil
}

// openPostgres creates PostgreSQL connection with connection pooling
func openPostgres(cfg *config.PostgresConfig) (*sql.DB, error) {
	// Expand password from environment if needed
	password := expandEnvVars(cfg.Password)

	// Build DSN
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		cfg.User,
		password,
		cfg.Host,
		cfg.Port,
		cfg.Database,
		cfg.SSLMode,
	)

	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))

	// Configure connection pool
	sqldb.SetMaxOpenConns(cfg.MaxOpenConns)
	sqldb.SetMaxIdleConns(cfg.MaxIdleConns)
	if cfg.ConnMaxLifetime != "" {
		duration, err := time.ParseDuration(cfg.ConnMaxLifetime)
		if err != nil {
			_ = sqldb.Close()
			return nil, fmt.Errorf("invalid conn_max_lifetime: %w", err)
		}
		sqldb.SetConnMaxLifetime(duration)
	}

	// Test connection
	if err := sqldb.Ping(); err != nil {
		_ = sqldb.Close()
		return nil, fmt.Errorf("failed to ping PostgreSQL: %w", err)
	}

	return sqldb, nil
}

// Close closes database connection
func (db *DB) Close() error {
	if db.ckptStop != nil {
		db.ckptStopOnce.Do(func() { close(db.ckptStop) })
	}
	// After the handle is closed, so our own descriptors are released first.
	defer reclaimSidecars(db.ownedSidecars)

	if db.DB != nil {
		// Persist query-planner statistics before closing so the next process to
		// reopen this database (e.g. `vigolium finding`/`traffic` read commands)
		// plans dedup/finding queries against real row counts rather than the
		// SQLite defaults.
		//
		// Skipped on a read-only handle: `PRAGMA optimize` rewrites sqlite_stat1,
		// which is a write to the very artifact --read-only promises not to touch.
		// query_only(1) would refuse it anyway, so this only stops an attempt that
		// was always going to fail — but attempting it at all is the wrong shape
		// for a mode whose entire contract is "no writes".
		if !db.readOnly {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			db.Optimize(ctx)
			cancel()
		}
		return db.DB.Close()
	}
	return nil
}

// Optimize refreshes the query-planner statistics so subsequent dedup and finding
// queries plan against real row counts. Call it after a bulk ingest phase (e.g.
// discovery) and before the heavy dedup passes; it also runs on Close and on the
// WAL checkpointer cadence. Best-effort — a failure degrades plans, never
// correctness.
//
// SQLite uses `PRAGMA optimize` (incremental: only re-analyzes tables that changed
// enough to matter). PostgreSQL analyzes just the hot ingest tables rather than
// the whole database, so a short-lived CLI run against a shared server doesn't
// trigger a blocking full-DB ANALYZE on every close.
func (db *DB) Optimize(ctx context.Context) {
	if db.DB == nil {
		return
	}
	// `PRAGMA optimize` writes sqlite_stat1. A read-only handle was opened
	// precisely so browsing a source cannot alter it, and query_only(1) would
	// reject the write anyway — leaving a debug-level error on every close of
	// every source file a glob touched.
	if db.readOnly {
		return
	}
	stmt := "PRAGMA optimize"
	if db.driver == "postgres" {
		stmt = "ANALYZE http_records, findings"
	}
	if _, err := db.ExecContext(ctx, stmt); err != nil {
		zap.L().Debug("query-planner optimize failed", zap.Error(err))
	}
}

// ftsIndexesBody reports whether an existing http_records_fts virtual table was
// created with the legacy body columns (raw_request/raw_response), so the caller
// knows to drop and recreate it as the slim metadata-only index. A missing table
// or query failure reports false — there is nothing to migrate.
func (db *DB) ftsIndexesBody(ctx context.Context) bool {
	var ddl string
	if err := db.QueryRowContext(ctx,
		"SELECT sql FROM sqlite_master WHERE type='table' AND name='http_records_fts'").Scan(&ddl); err != nil {
		return false
	}
	return strings.Contains(ddl, "raw_request") || strings.Contains(ddl, "raw_response")
}

// recordSecondaryIndexes are the non-unique read indexes on http_records.
//
// They are kept apart from the rest of CreateSchema's index list because they
// are the only ones a BULK LOAD can safely postpone: nothing depends on them for
// correctness (uuid is the PRIMARY KEY, and that is what the merge's
// INSERT OR IGNORE dedups on), and they are the most expensive to maintain
// incrementally — thirteen b-tree insertions per row, most of them keyed on a
// random uuid, so every insert dirties thirteen pages in thirteen different
// places. Building them once after the rows are in lets SQLite sort instead.
//
// See DeferRecordIndexes for who postpones them, and CreateRecordIndexes for
// when they are built.
var recordSecondaryIndexes = []string{
	// -- http_records: project-aware composite indexes --
	"CREATE INDEX IF NOT EXISTS idx_records_project_hostname ON http_records(project_uuid, hostname)",
	"CREATE INDEX IF NOT EXISTS idx_records_project_created_uuid ON http_records(project_uuid, created_at, uuid)",
	"CREATE INDEX IF NOT EXISTS idx_records_project_sent_at ON http_records(project_uuid, sent_at)",
	"CREATE INDEX IF NOT EXISTS idx_records_project_host_method_status ON http_records(project_uuid, hostname, method, status_code)",
	"CREATE INDEX IF NOT EXISTS idx_records_project_scheme_host_port ON http_records(project_uuid, scheme, hostname, port)",
	"CREATE INDEX IF NOT EXISTS idx_records_project_risk_score ON http_records(project_uuid, risk_score)",
	"CREATE INDEX IF NOT EXISTS idx_records_project_surface_score ON http_records(project_uuid, surface_score)",
	// Covering index for findDuplicateRecord: the duplicate probe filters on
	// (project_uuid, method, hostname, path, url[, request_hash]) and selects
	// only uuid. Indexing all of those plus uuid lets the lookup resolve
	// entirely from the index (no per-candidate table row fetch). The old
	// 4-column version (…, path) is dropped in CreateSchema so this definition
	// takes effect on existing databases.
	"CREATE INDEX IF NOT EXISTS idx_records_dedup ON http_records(project_uuid, method, hostname, path, url, request_hash, uuid)",
	"CREATE INDEX IF NOT EXISTS idx_records_request_hash ON http_records(request_hash)",
	"CREATE INDEX IF NOT EXISTS idx_records_response_hash ON http_records(response_hash)",
	// Supports DeduplicateDeparosByNormHash: narrows the full http_records scan to
	// the (project, deparos) subset and surfaces response_norm_hash for the
	// reflected-URL-robust dedup pass run after discovery.
	"CREATE INDEX IF NOT EXISTS idx_records_norm_hash ON http_records(project_uuid, source, response_norm_hash)",
	// -- http_records: scan_uuid index --
	"CREATE INDEX IF NOT EXISTS idx_records_project_scan ON http_records(project_uuid, scan_uuid)",
	// -- http_records: source-filtered cursor scan (scan-on-receive) --
	// Supports WHERE source IN (...) AND created_at > cursor filters in
	// DBInputSource.fetchNextBatch and Repository.CountRecordsAfterCursorBySource.
	"CREATE INDEX IF NOT EXISTS idx_records_project_source_created ON http_records(project_uuid, source, created_at, uuid)",
}

// DeferRecordIndexes tells CreateSchema to leave the http_records read indexes
// uncreated, so a bulk load runs against the primary key alone. The caller MUST
// call CreateRecordIndexes once loading is done — a store left without them is
// schema-complete but plans every read as a full scan.
//
// Only for disposable stores that are filled once and then read (the --glob-db
// scratch merge). A persistent store must not defer: it is written to
// continuously, so there is no "after the load" to build them in.
func (db *DB) DeferRecordIndexes() { db.deferRecordIndexes = true }

// CreateRecordIndexes builds the http_records read indexes. Idempotent (every
// statement is IF NOT EXISTS), so calling it on a store that never deferred is
// harmless.
func (db *DB) CreateRecordIndexes(ctx context.Context) error {
	for _, ddl := range recordSecondaryIndexes {
		if _, err := db.ExecContext(ctx, ddl); err != nil {
			return fmt.Errorf("failed to create record index: %w", err)
		}
	}
	return nil
}

// rebuildFTSIfPopulated repopulates the search index from http_records, once,
// after the index has been created or replaced.
//
// It is skipped for an empty table: on a fresh database there is nothing to
// index and the triggers cover everything from here on, so the common case pays
// one COUNT rather than a rebuild. Best-effort — a failure leaves searches
// falling back to the LIKE scan, which is slower but correct.
func (db *DB) rebuildFTSIfPopulated(ctx context.Context) {
	var rows int64
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM http_records").Scan(&rows); err != nil || rows == 0 {
		return
	}
	zap.L().Debug("rebuilding full-text search index", zap.Int64("records", rows))
	db.execBestEffort(ctx, "rebuild FTS index",
		"INSERT INTO http_records_fts(http_records_fts) VALUES('rebuild')")
}

// Driver returns the database driver name
func (db *DB) Driver() string {
	return db.driver
}

// Path returns the resolved SQLite file backing this handle, or "" for a driver
// that is not a single file (Postgres).
//
// It exists because DatabaseStats.Database.Path and .Size were declared and
// never filled: `db stats -j` reported `"path": "", "size": 0` for a store it
// had open and had just counted 60 records in. A consumer reading that to
// confirm WHICH database it was looking at — the whole reason the -j envelope
// carries db_path — was told nothing, in a field that looked like an answer.
func (db *DB) Path() string {
	return db.path
}

// SQLDB returns the underlying *sql.DB. Used by callers that need a pinned
// *sql.Conn for connection-scoped operations (e.g. ATTACH DATABASE during a
// SQLite-to-SQLite merge) that must run on a single physical connection.
func (db *DB) SQLDB() *sql.DB {
	return db.DB.DB
}

// ExpandPath resolves ~ and environment variables in a filesystem path using
// the same rules as the SQLite DSN builder. Exported so callers (e.g. the
// merge lock) can derive sidecar paths next to the real database file.
func ExpandPath(path string) string {
	return expandPath(path)
}

// HasFTS reports whether full-text search is available on this handle (FTS5 for
// SQLite, tsvector for PostgreSQL).
//
// It DISCOVERS the answer rather than remembering whether this process created
// the index. It used to be a plain field assigned only by SeedDefaults, which
// made the answer depend on how the handle was opened rather than on what the
// database contains: `vigolium server` seeds and reported true, every read
// command (traffic, finding, db ls) does not seed and reported false on the very
// same file. Two commands then took different query paths over one database.
//
// Discovery is lazy and cached: a handle that never searches pays nothing, and
// one that does pays a single sqlite_master lookup.
func (db *DB) HasFTS() bool {
	db.ftsMu.Lock()
	defer db.ftsMu.Unlock()
	if !db.ftsKnown {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		db.hasFTS = db.detectFTS(ctx)
		cancel()
		db.ftsKnown = true
	}
	return db.hasFTS
}

// setFTS records a known capability, for the paths that just created or dropped
// the index and need not re-discover it.
func (db *DB) setFTS(available bool) {
	db.ftsMu.Lock()
	db.hasFTS = available
	db.ftsKnown = true
	db.ftsMu.Unlock()
}

// detectFTS inspects the database for a USABLE search index.
//
// "Usable" is stricter than "present" on SQLite, and deliberately so: the index
// is an external-content FTS5 table kept current by triggers, so a table without
// its insert trigger is a table that silently stops matching anything written
// after the trigger went missing. Reporting false there costs a slower LIKE scan;
// reporting true costs correct-looking empty results.
func (db *DB) detectFTS(ctx context.Context) bool {
	if db.driver == "postgres" {
		var n int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM information_schema.columns
			 WHERE table_name = 'http_records' AND column_name = 'search_vector'`).Scan(&n); err != nil {
			return false
		}
		return n > 0
	}

	if db.ftsIndexesBody(ctx) {
		// A legacy body-indexed table is migrated away by SeedDefaults; until then
		// its column set does not match the queries in query.go.
		return false
	}
	if !db.tableExists(ctx, "http_records_fts") {
		return false
	}
	var triggers int
	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name = 'http_records_fts_ai'").Scan(&triggers); err != nil {
		return false
	}
	return triggers == 1
}

// ServerVersion returns the database server version string (e.g. the Postgres
// "PostgreSQL 16.1 ..." banner or the SQLite library version).
func (db *DB) ServerVersion(ctx context.Context) (string, error) {
	var query string
	switch db.driver {
	case "postgres":
		query = "SELECT version()"
	case "sqlite":
		query = "SELECT sqlite_version()"
	default:
		return "", fmt.Errorf("unsupported driver: %s", db.driver)
	}
	var version string
	if err := db.QueryRowContext(ctx, query).Scan(&version); err != nil {
		return "", err
	}
	return strings.TrimSpace(version), nil
}

// adaptDDL rewrites SQLite-specific DDL for PostgreSQL when needed.
func (db *DB) adaptDDL(ddl string) string {
	if db.driver != "postgres" {
		return ddl
	}
	ddl = strings.ReplaceAll(ddl, "INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
	ddl = strings.ReplaceAll(ddl, "BLOB", "BYTEA")
	// SQLite uses INTEGER for booleans; PostgreSQL needs BOOLEAN
	ddl = strings.ReplaceAll(ddl, "has_response INTEGER NOT NULL DEFAULT 0", "has_response BOOLEAN NOT NULL DEFAULT FALSE")
	ddl = strings.ReplaceAll(ddl, "is_authenticated INTEGER NOT NULL DEFAULT 0", "is_authenticated BOOLEAN NOT NULL DEFAULT FALSE")
	ddl = strings.ReplaceAll(ddl, "enabled INTEGER NOT NULL DEFAULT 1", "enabled BOOLEAN NOT NULL DEFAULT TRUE")
	ddl = strings.ReplaceAll(ddl, "complete INTEGER NOT NULL DEFAULT 0", "complete BOOLEAN NOT NULL DEFAULT FALSE")
	return ddl
}

// currentSchemaVersion is the schema revision this binary expects. Bump it when
// adding a new one-time backfill/migration in CreateSchema so it re-runs once on
// existing databases. A database already at this version skips the O(rows)
// backfills and legacy-index reshaping, so a current database opens in roughly
// constant time regardless of how many records it holds (rather than re-scanning
// every table and rebuilding the covering index on every process start).
const currentSchemaVersion = 1

// CurrentSchemaVersion exposes the schema revision this binary expects, so a
// consumer can fail loudly on drift at startup (`vigolium version --json`)
// rather than discovering it as a query error mid-run.
func CurrentSchemaVersion() int { return currentSchemaVersion }

// schemaVersion reads the recorded schema version, or 0 when unset (a fresh
// database, or one created before versioning). Requires schema_meta to exist.
func (db *DB) schemaVersion(ctx context.Context) int {
	var v int
	if err := db.QueryRowContext(ctx, "SELECT version FROM schema_meta WHERE id = 1").Scan(&v); err != nil {
		return 0
	}
	return v
}

// setSchemaVersion records the schema version so later opens can skip the
// one-time backfills. Best-effort: a failure just re-runs them next open.
func (db *DB) setSchemaVersion(ctx context.Context, v int) {
	db.execBestEffort(ctx, "record schema version",
		"INSERT INTO schema_meta (id, version) VALUES (1, ?) ON CONFLICT (id) DO UPDATE SET version = excluded.version",
		v)
}

// CreateSchema creates all database tables and indexes if they don't exist.
//
// It is a no-op on a read-only handle. The read commands call it on open to
// self-heal a fresh project database; against a source opened --read-only that
// would be a schema write to someone else's evidence, and a source genuinely
// missing the tables surfaces as a query error rather than being silently
// migrated into the current shape.
func (db *DB) CreateSchema(ctx context.Context) error {
	if db.readOnly {
		// A read-only handle cannot be migrated — `mode=ro` refuses DDL — so the
		// best it can do is report a schema it will not be able to query. Without
		// this the caller's first SELECT fails with a bare
		// "no such column: r.surface_score", which names a symptom and no remedy.
		return db.checkSchemaCurrent(ctx)
	}
	tables := []string{
		// Schema versioning: lets CreateSchema skip one-time O(rows) backfills once
		// a database is current (see currentSchemaVersion). Single row, id always 1.
		`CREATE TABLE IF NOT EXISTS schema_meta (
			id INTEGER PRIMARY KEY,
			version INTEGER NOT NULL DEFAULT 0
		)`,
		// Multi-tenancy: users and projects
		`CREATE TABLE IF NOT EXISTS users (
			uuid TEXT PRIMARY KEY NOT NULL,
			email TEXT,
			name TEXT,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS projects (
			uuid TEXT PRIMARY KEY NOT NULL,
			name TEXT NOT NULL,
			description TEXT,
			owner_uuid TEXT,
			config_path TEXT,
			tags TEXT,
			default_target TEXT,
			last_scan_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS scans (
			uuid TEXT PRIMARY KEY NOT NULL,
			project_uuid TEXT NOT NULL,
			name TEXT,
			description TEXT,
			status TEXT NOT NULL DEFAULT 'running',
			target TEXT,
			modules TEXT,
			threads INTEGER DEFAULT 0,
			profile TEXT,
			source_path TEXT,
			source_type TEXT,
			tags TEXT,
			triggered_by TEXT,
			agentic_scan_uuid TEXT,
			http_record_uuid TEXT,
			scan_source TEXT,
			scan_mode TEXT,
			start_cursor_at TIMESTAMP,
			start_cursor_uuid TEXT,
			cursor_at TIMESTAMP,
			cursor_uuid TEXT,
			processed_count INTEGER DEFAULT 0,
			started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			finished_at TIMESTAMP,
			duration_ms INTEGER DEFAULT 0,
			total_requests INTEGER DEFAULT 0,
			total_findings INTEGER DEFAULT 0,
			critical_count INTEGER DEFAULT 0,
			high_count INTEGER DEFAULT 0,
			medium_count INTEGER DEFAULT 0,
			low_count INTEGER DEFAULT 0,
			info_count INTEGER DEFAULT 0,
			suspect_count INTEGER DEFAULT 0,
			error_message TEXT,
			storage_url TEXT,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS http_records (
			uuid TEXT PRIMARY KEY NOT NULL,
			project_uuid TEXT NOT NULL,
			scan_uuid TEXT,
			scheme TEXT NOT NULL,
			hostname TEXT NOT NULL,
			port INTEGER NOT NULL,
			ip TEXT,
			method TEXT NOT NULL,
			path TEXT NOT NULL,
			url TEXT NOT NULL,
			http_version TEXT NOT NULL,
			request_content_type TEXT,
			request_content_length INTEGER DEFAULT 0,
			raw_request BLOB,
			request_hash TEXT NOT NULL,
			request_authorization TEXT,
			status_code INTEGER DEFAULT 0,
			status_phrase TEXT,
			response_http_version TEXT,
			response_content_type TEXT,
			response_content_length INTEGER DEFAULT 0,
			raw_response BLOB,
			response_hash TEXT,
			response_norm_hash TEXT,
			response_time_ms INTEGER DEFAULT 0,
			response_words INTEGER DEFAULT 0,
			has_response INTEGER NOT NULL DEFAULT 0,
			response_title TEXT,
			response_location TEXT,
			parameters TEXT,
			sent_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			received_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			source TEXT DEFAULT '',
			technology TEXT,
			content_hash TEXT,
			is_authenticated INTEGER NOT NULL DEFAULT 0,
			parent_uuid TEXT,
			remarks TEXT,
			risk_score INTEGER DEFAULT 0,
			surface_score INTEGER DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS analysis_artifacts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			project_uuid TEXT NOT NULL,
			scan_uuid TEXT,
			http_record_uuid TEXT NOT NULL,
			kind TEXT NOT NULL,
			filename TEXT,
			media_type TEXT,
			sha256 TEXT NOT NULL,
			byte_length INTEGER NOT NULL,
			content BLOB NOT NULL,
			metadata TEXT,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS findings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			project_uuid TEXT NOT NULL,
			http_record_uuids TEXT NOT NULL,
			scan_uuid TEXT,
			agentic_scan_uuid TEXT,
			url TEXT,
			hostname TEXT,
			module_id TEXT NOT NULL,
			module_name TEXT NOT NULL,
			module_type TEXT DEFAULT '',
			finding_source TEXT DEFAULT '',
			record_kind TEXT NOT NULL DEFAULT 'finding',
			evidence_grade TEXT DEFAULT '',
			module_short TEXT DEFAULT '',
			description TEXT,
			severity TEXT NOT NULL,
			confidence TEXT NOT NULL DEFAULT 'firm',
			tags TEXT,
			status TEXT DEFAULT 'triaged',
			remediation TEXT,
			cwe_id TEXT,
			cvss_score REAL DEFAULT 0,
			source_file TEXT,
			repo_name TEXT,
			matched_at TEXT,
			extracted_results TEXT,
			additional_evidence TEXT,
			request TEXT,
			response TEXT,
			finding_hash TEXT NOT NULL,
			found_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS finding_records (
			finding_id INTEGER NOT NULL,
			record_uuid TEXT NOT NULL,
			PRIMARY KEY (finding_id, record_uuid)
		)`,
		`CREATE TABLE IF NOT EXISTS scopes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			project_uuid TEXT NOT NULL,
			name TEXT NOT NULL,
			description TEXT,
			rule_type TEXT NOT NULL,
			host_pattern TEXT,
			path_pattern TEXT,
			content_type_pattern TEXT,
			methods TEXT,
			ports TEXT,
			schemes TEXT,
			priority INTEGER NOT NULL DEFAULT 100,
			enabled INTEGER NOT NULL DEFAULT 1,
			hit_count INTEGER DEFAULT 0,
			last_matched_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS oast_interactions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			project_uuid TEXT NOT NULL,
			scan_uuid TEXT,
			unique_id TEXT NOT NULL,
			full_id TEXT NOT NULL,
			protocol TEXT NOT NULL,
			q_type TEXT,
			raw_request TEXT,
			raw_response TEXT,
			remote_address TEXT,
			interacted_at TIMESTAMP NOT NULL,
			target_url TEXT,
			parameter_name TEXT,
			injection_type TEXT,
			module_id TEXT,
			finding_id INTEGER,
			payload TEXT,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS agentic_scans (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			uuid TEXT NOT NULL UNIQUE,
			project_uuid TEXT NOT NULL,
			scan_uuid TEXT,
			mode TEXT NOT NULL,
			agent_name TEXT NOT NULL,
			input_raw TEXT,
			input_type TEXT,
			target_url TEXT,
			vuln_type TEXT,
			module_names TEXT,
			template_id TEXT,
			status TEXT NOT NULL DEFAULT 'pending',
			current_phase TEXT,
			phases_run TEXT,
			finding_count INTEGER DEFAULT 0,
			record_count INTEGER DEFAULT 0,
			saved_count INTEGER DEFAULT 0,
			source_path TEXT,
			source_type TEXT,
			token_usage TEXT,
			retry_count INTEGER DEFAULT 0,
			parent_run_uuid TEXT,
			input_record_count INTEGER DEFAULT 0,
			attack_plan TEXT,
			triage_result TEXT,
			prompt_sent TEXT,
			agent_raw_output TEXT,
			error_message TEXT,
			result_json TEXT,
			storage_url TEXT,
			session_id TEXT,
			session_dir TEXT,
			started_at TIMESTAMP,
			completed_at TIMESTAMP,
			duration_ms INTEGER DEFAULT 0,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS authentication_hostnames (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			project_uuid TEXT NOT NULL,
			scan_uuid TEXT,
			hostname TEXT NOT NULL,
			session_name TEXT NOT NULL,
			session_role TEXT DEFAULT '',
			position INTEGER DEFAULT 0,
			session_token TEXT,
			headers TEXT,
			login_url TEXT,
			login_method TEXT,
			login_content_type TEXT,
			login_body TEXT,
			login_request TEXT,
			login_response TEXT,
			extract_rules TEXT,
			source TEXT DEFAULT '',
			hydrated_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		// One row per (run, endpoint): what this scan observed about a HOST, as
		// opposed to about one exchange with it.
		//
		// Normalized rather than stored on http_records. The per-row objection
		// that keeps the full DNS answer off the record still stands — a sweep
		// writes several rows per host and a redirect chain alone is three, so
		// columns would hold many identical copies of one answer — but it is an
		// argument against DUPLICATING the answer, not against keeping it. Here
		// it is written once per endpoint per run and referenced by hostname and
		// port.
		//
		// Keyed by scan_uuid so a re-probe RECORDS a new observation instead of
		// overwriting the old one: "what did the host resolve to when we scanned
		// it in March" is a question a report has to be able to answer, and an
		// upsert keyed on hostname alone would destroy the answer every time the
		// host was scanned again. UNIQUE(scan_uuid, hostname, port) makes a
		// repeat within ONE run idempotent, which is the only case where
		// overwriting is correct.
		//
		// complete distinguishes a lookup that ran and found nothing from one
		// that was cut short (a cancelled or budget-limited prefetch). Without
		// it an empty answer is unreadable: "this host has no AAAA record" and
		// "we never got to this host" are different facts about the scan.
		`CREATE TABLE IF NOT EXISTS host_observations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			project_uuid TEXT NOT NULL,
			scan_uuid TEXT,
			hostname TEXT NOT NULL,
			port INTEGER NOT NULL DEFAULT 0,
			observed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			dns_a TEXT,
			dns_aaaa TEXT,
			dns_cname TEXT,
			tls TEXT,
			complete INTEGER NOT NULL DEFAULT 0,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(scan_uuid, hostname, port)
		)`,
		`CREATE TABLE IF NOT EXISTS scan_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			project_uuid TEXT NOT NULL,
			scan_uuid TEXT NOT NULL,
			level TEXT NOT NULL,
			phase TEXT,
			message TEXT NOT NULL,
			metadata TEXT,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		// Durable autopilot: one row per bounded operator section (a Reset() +
		// reconstructed-brief cycle). Only written when autopilot_mode != legacy.
		`CREATE TABLE IF NOT EXISTS agent_sections (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			uuid TEXT NOT NULL UNIQUE,
			agentic_scan_uuid TEXT,
			project_uuid TEXT,
			seq INTEGER NOT NULL DEFAULT 0,
			kind TEXT,
			status TEXT NOT NULL DEFAULT 'running',
			task TEXT,
			closing_summary TEXT,
			rotation_reason TEXT,
			turn_count INTEGER NOT NULL DEFAULT 0,
			input_tokens INTEGER NOT NULL DEFAULT 0,
			output_tokens INTEGER NOT NULL DEFAULT 0,
			error_message TEXT,
			started_at TIMESTAMP,
			ended_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		// Durable autopilot: verify-before-promote candidates. Each proposed
		// finding lands here first (status=proposed), a fresh-context verifier
		// grades it, and confirmed ones are promoted into findings. Only
		// written when autopilot_mode != legacy. UNIQUE(agentic_scan_uuid,
		// dedup_hash) backs the ON CONFLICT dedup on SaveCandidate.
		`CREATE TABLE IF NOT EXISTS agent_finding_candidates (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			uuid TEXT NOT NULL UNIQUE,
			agentic_scan_uuid TEXT,
			project_uuid TEXT,
			section_uuid TEXT,
			title TEXT,
			severity TEXT,
			description TEXT,
			remediation TEXT,
			cwe_id TEXT,
			source_file TEXT,
			url TEXT,
			hostname TEXT,
			confidence TEXT,
			class TEXT,
			status TEXT NOT NULL DEFAULT 'proposed',
			verdict_reason TEXT,
			evidence_grade TEXT,
			record_uuids TEXT,
			oast_ids TEXT,
			request TEXT,
			response TEXT,
			dedup_hash TEXT NOT NULL DEFAULT '',
			promoted_finding_id INTEGER NOT NULL DEFAULT 0,
			tags TEXT,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			verified_at TIMESTAMP
		)`,
	}

	zap.L().Debug("Initializing database tables")
	for _, ddl := range tables {
		if _, err := db.ExecContext(ctx, db.adaptDDL(ddl)); err != nil {
			return fmt.Errorf("failed to create table: %w", err)
		}
	}

	// A database already at currentSchemaVersion has had the one-time backfills and
	// legacy-index reshaping below applied, so skip them — they scan/rewrite whole
	// tables and would otherwise run on every open. Cheap idempotent DDL (CREATE
	// TABLE/INDEX IF NOT EXISTS, ADD COLUMN) still runs unconditionally so the
	// schema stays self-healing.
	schemaCurrent := db.schemaVersion(ctx) >= currentSchemaVersion

	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_analysis_artifacts_project_record ON analysis_artifacts(project_uuid, http_record_uuid)",
		"CREATE INDEX IF NOT EXISTS idx_analysis_artifacts_scan ON analysis_artifacts(scan_uuid)",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_analysis_artifacts_record_kind_hash ON analysis_artifacts(http_record_uuid, kind, sha256)",

		// -- host_observations --
		// The read is "what did this run see for this endpoint", issued once per
		// emitted record, so (project, scan, hostname, port) is the exact lookup.
		// The scan-less variant backs the fallback read for a caller that knows
		// the project but not which run to trust, which takes the most recent.
		// The only index this table needs beyond its UNIQUE(scan_uuid, hostname,
		// port) constraint. It covers the project-wide read - newest observation
		// for an endpoint, ORDER BY id DESC LIMIT 1 - with id in the index so the
		// lookup never fetches a table row per observation. The scan-scoped read
		// is served by the unique constraint's own index, so a third
		// (project_uuid, scan_uuid, hostname, port) index bought nothing and cost
		// a b-tree insertion on every observation written.
		"CREATE INDEX IF NOT EXISTS idx_host_obs_project_host_id ON host_observations(project_uuid, hostname, port, id)",

		// -- findings: project-aware composite indexes --
		"CREATE INDEX IF NOT EXISTS idx_findings_project_severity ON findings(project_uuid, severity)",
		"CREATE INDEX IF NOT EXISTS idx_findings_project_module ON findings(project_uuid, module_id)",
		"CREATE INDEX IF NOT EXISTS idx_findings_project_found_at ON findings(project_uuid, found_at)",
		"CREATE INDEX IF NOT EXISTS idx_findings_project_module_type ON findings(project_uuid, module_type)",
		"CREATE INDEX IF NOT EXISTS idx_findings_project_finding_source ON findings(project_uuid, finding_source)",
		"CREATE INDEX IF NOT EXISTS idx_findings_project_record_kind ON findings(project_uuid, record_kind)",
		"CREATE INDEX IF NOT EXISTS idx_findings_project_scan ON findings(project_uuid, scan_uuid)",
		// Covers aggregateScanFindings (SELECT severity, COUNT(*) WHERE scan_uuid = ?
		// GROUP BY severity), which runs on every scan-status tick. scan_uuid is not
		// the leading column of idx_findings_project_scan, so without this the count
		// fell back to a full findings scan each tick; (scan_uuid, severity) makes it
		// index-only.
		"CREATE INDEX IF NOT EXISTS idx_findings_scan_severity ON findings(scan_uuid, severity)",
		"CREATE INDEX IF NOT EXISTS idx_findings_project_status ON findings(project_uuid, status)",
		"CREATE INDEX IF NOT EXISTS idx_findings_project_hostname ON findings(project_uuid, hostname)",
		// Backs the per-round dynamic-assessment dedup grouping
		// (DeduplicateFindings / GroupFindingsByValue): the WHERE narrows on
		// (project_uuid, hostname) and the window function partitions by
		// (module_id, severity, …) ordered by created_at. Indexing all five lets
		// the host-scoped scan resolve from the index and arrive partially
		// pre-ordered for the PARTITION BY, instead of a full findings scan + sort
		// every feedback round. (matched_url is a json_extract expression and
		// stays per-row, but the module_id/severity prefix is satisfied here.)
		"CREATE INDEX IF NOT EXISTS idx_findings_project_host_module_sev ON findings(project_uuid, hostname, module_id, severity, created_at)",
		// Sparse (nullzero column) — used by agent end-of-run summaries and
		// webhook notifications to count findings per agentic-scan run.
		"CREATE INDEX IF NOT EXISTS idx_findings_agentic_scan ON findings(agentic_scan_uuid)",
		// Dedup is scoped per project: the same finding_hash may legitimately
		// recur across projects without one project's finding suppressing
		// another's. Backs ON CONFLICT (project_uuid, finding_hash).
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_project_hash_unique ON findings(project_uuid, finding_hash)",

		// -- finding_records --
		"CREATE INDEX IF NOT EXISTS idx_finding_records_record_uuid ON finding_records(record_uuid)",
		"CREATE INDEX IF NOT EXISTS idx_finding_records_finding_id ON finding_records(finding_id)",

		// -- scans --
		"CREATE INDEX IF NOT EXISTS idx_scans_project_status ON scans(project_uuid, status)",
		"CREATE INDEX IF NOT EXISTS idx_scans_project_created ON scans(project_uuid, created_at)",

		// -- scopes --
		"CREATE INDEX IF NOT EXISTS idx_scopes_project_enabled_priority ON scopes(project_uuid, enabled, priority)",

		// -- oast_interactions --
		"CREATE INDEX IF NOT EXISTS idx_oast_project_scan ON oast_interactions(project_uuid, scan_uuid)",
		"CREATE INDEX IF NOT EXISTS idx_oast_interactions_unique_id ON oast_interactions(unique_id)",

		// -- agentic_scans --
		"CREATE INDEX IF NOT EXISTS idx_agentic_scans_uuid ON agentic_scans(uuid)",
		"CREATE INDEX IF NOT EXISTS idx_agentic_scans_project_status ON agentic_scans(project_uuid, status)",
		"CREATE INDEX IF NOT EXISTS idx_agentic_scans_project_created ON agentic_scans(project_uuid, created_at)",
		"CREATE INDEX IF NOT EXISTS idx_agentic_scans_scan ON agentic_scans(scan_uuid)",

		// -- authentication_hostnames --
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_authentication_hostnames_unique ON authentication_hostnames(project_uuid, hostname, session_name)",
		"CREATE INDEX IF NOT EXISTS idx_authentication_hostnames_project_hostname ON authentication_hostnames(project_uuid, hostname)",
		"CREATE INDEX IF NOT EXISTS idx_authentication_hostnames_project_scan ON authentication_hostnames(project_uuid, scan_uuid)",

		// -- scan_logs --
		"CREATE INDEX IF NOT EXISTS idx_scan_logs_project_scan ON scan_logs(project_uuid, scan_uuid)",
		"CREATE INDEX IF NOT EXISTS idx_scan_logs_created_at ON scan_logs(created_at)",

		// -- projects --
		"CREATE INDEX IF NOT EXISTS idx_projects_owner ON projects(owner_uuid)",

		// -- agent_sections (durable autopilot) --
		"CREATE INDEX IF NOT EXISTS idx_agent_sections_agentic_scan ON agent_sections(agentic_scan_uuid, seq)",
		"CREATE INDEX IF NOT EXISTS idx_agent_sections_project ON agent_sections(project_uuid)",

		// -- agent_finding_candidates (durable autopilot) --
		"CREATE INDEX IF NOT EXISTS idx_agent_candidates_agentic_scan ON agent_finding_candidates(agentic_scan_uuid, status)",
		"CREATE INDEX IF NOT EXISTS idx_agent_candidates_project ON agent_finding_candidates(project_uuid)",
		// Backs ON CONFLICT (agentic_scan_uuid, dedup_hash) DO NOTHING in SaveCandidate.
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_candidates_dedup ON agent_finding_candidates(agentic_scan_uuid, dedup_hash)",
	}

	// Drop old indexes before creating the correct ones (migration for existing
	// databases). Gated on schema version: once applied, the indexes already have
	// their new shape, and re-dropping idx_records_dedup here would force a full
	// covering-index rebuild (O(records)) on every open. Must run before CREATE
	// UNIQUE INDEX so the unconditional unique index survives. idx_findings_hash_unique
	// was a global UNIQUE(finding_hash) — superseded by the project-scoped
	// idx_findings_project_hash_unique below; dropping it lets the same finding_hash
	// coexist across projects.
	if !schemaCurrent {
		db.execBestEffort(ctx, "drop legacy index idx_findings_hash", "DROP INDEX IF EXISTS idx_findings_hash")
		db.execBestEffort(ctx, "drop legacy index idx_findings_hash_unique", "DROP INDEX IF EXISTS idx_findings_hash_unique")

		// idx_records_dedup was (project_uuid, method, hostname, path); it is
		// recreated below as a covering index that also includes url, request_hash,
		// and uuid so findDuplicateRecord resolves without a table fetch. Drop the
		// old definition so the CREATE INDEX IF NOT EXISTS below actually applies on
		// existing databases (IF NOT EXISTS would otherwise keep the stale shape).
		db.execBestEffort(ctx, "drop legacy index idx_records_dedup", "DROP INDEX IF EXISTS idx_records_dedup")

		// Drop old single-column indexes superseded by project-aware composites
		oldIndexes := []string{
			"idx_records_hostname", "idx_records_method", "idx_records_status_code",
			"idx_records_sent_at", "idx_records_host_method_status", "idx_records_scheme_host_port",
			"idx_records_risk_score", "idx_records_created_at_uuid",
			"idx_findings_module_id", "idx_findings_severity", "idx_findings_found_at", "idx_findings_scan_uuid",
			"idx_scans_status", "idx_scans_started_at",
			"idx_scopes_enabled_priority",
			"idx_oast_interactions_scan_uuid",
			"idx_scan_logs_scan_uuid",
		}
		for _, idx := range oldIndexes {
			db.execBestEffort(ctx, "drop legacy index "+idx, "DROP INDEX IF EXISTS "+idx)
		}
	}

	// Column migrations for existing databases — MUST run before the index loop
	// (moved below). Several indexes reference columns added here, e.g.
	// idx_records_norm_hash → http_records.response_norm_hash. The index loop
	// aborts CreateSchema on the first error, so building a new column's index
	// before the column exists fails schema init entirely and leaves repo nil.
	db.runColumnMigrations(ctx)

	// Create indexes now that all column migrations above have run — some indexes
	// reference newly added columns (e.g. idx_records_norm_hash → response_norm_hash).
	for _, ddl := range indexes {
		if _, err := db.ExecContext(ctx, ddl); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}
	if !db.deferRecordIndexes {
		if err := db.CreateRecordIndexes(ctx); err != nil {
			return err
		}
	}

	// One-time O(rows) backfills. Gated on schema version: each scans a whole table
	// (or every finding's JSON), so re-running them on every open makes startup
	// scale with database size. New rows are written with correct values by the
	// write paths, so these only reconcile pre-versioning legacy data.
	if !schemaCurrent {
		// Backfill empty project_uuid values — Bun ORM inserts explicit empty strings
		// which bypass the column DEFAULT, so rows created before ProjectUUID was
		// propagated through all code paths end up with project_uuid = ''.
		for _, table := range projectUUIDMigrationTables {
			db.execBestEffort(ctx, "backfill project_uuid on "+table,
				fmt.Sprintf("UPDATE %s SET project_uuid = ? WHERE project_uuid = ''", table),
				DefaultProjectUUID)
		}

		// Migrate legacy finding statuses: 'open' and 'confirmed' both collapse to
		// 'triaged' in the current state model (see models.Status* constants).
		db.execBestEffort(ctx, "migrate legacy finding statuses",
			"UPDATE findings SET status = ? WHERE status IN (?, ?)",
			StatusTriaged, "open", "confirmed")

		// Backfill finding_records from existing JSONB data (idempotent)
		if db.driver == "postgres" {
			db.execBestEffort(ctx, "backfill finding_records", `
				INSERT INTO finding_records (finding_id, record_uuid)
				SELECT f.id, je
				FROM findings f, jsonb_array_elements_text(f.http_record_uuids::jsonb) AS je
				WHERE f.http_record_uuids IS NOT NULL AND f.http_record_uuids != '' AND f.http_record_uuids != '[]'
				ON CONFLICT DO NOTHING
			`)
		} else {
			db.execBestEffort(ctx, "backfill finding_records", `
				INSERT OR IGNORE INTO finding_records (finding_id, record_uuid)
				SELECT f.id, je.value
				FROM findings f, json_each(f.http_record_uuids) AS je
			`)
		}
	}

	// Record the version so the next open can skip the gated work above. Done last
	// so a failure partway through leaves the version unset and the migrations retry.
	db.setSchemaVersion(ctx, currentSchemaVersion)

	return nil
}

// SeedDefaults creates the default user and project if they don't exist.
// This is called during initialization to ensure CLI has a working project context.
func (db *DB) SeedDefaults(ctx context.Context) error {
	if db.driver == "postgres" {
		db.execBestEffort(ctx, "seed default user",
			"INSERT INTO users (uuid, name, email, created_at, updated_at) VALUES (?, ?, '', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) ON CONFLICT (uuid) DO NOTHING",
			DefaultUserUUID, "vigolium-admin")
		db.execBestEffort(ctx, "seed default project",
			"INSERT INTO projects (uuid, name, description, owner_uuid, created_at, updated_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) ON CONFLICT (uuid) DO NOTHING",
			DefaultProjectUUID, "Default Project", "Auto-created default project", DefaultUserUUID)
	} else {
		db.execBestEffort(ctx, "seed default user",
			"INSERT OR IGNORE INTO users (uuid, name, email, created_at, updated_at) VALUES (?, ?, '', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
			DefaultUserUUID, "vigolium-admin")
		db.execBestEffort(ctx, "seed default project",
			"INSERT OR IGNORE INTO projects (uuid, name, description, owner_uuid, created_at, updated_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
			DefaultProjectUUID, "Default Project", "Auto-created default project", DefaultUserUUID)
	}

	// Create FTS5 index for full-text search on HTTP records (SQLite only).
	//
	// Only the cheap metadata columns (url, path, hostname) are indexed. The
	// large raw_request/raw_response blobs are deliberately NOT in the FTS index:
	// indexing them forced every record INSERT to CAST both blobs to TEXT and
	// re-tokenize multi-KB bodies inline in the write transaction — roughly
	// doubling steady-state ingest write volume purely to accelerate the rare
	// body/header search. Body/header searches now use the CAST(...) LIKE scan in
	// query.go (applyRawCorpusSearch); see also the legacy-table cleanup below
	// which drops a previously body-indexed FTS so the slim definition applies.
	if db.driver != "postgres" {
		// Whether the index has to be (re)populated is decided BEFORE any DDL
		// runs, because both answers stop being observable once it has.
		//
		// An external-content FTS5 table is created EMPTY: its rows come from the
		// triggers below, which only fire on writes that happen afterwards. So a
		// database that already holds traffic — one upgrading from no index, or
		// from the legacy body-indexed one — gets a table that matches nothing
		// ever written before this moment, while HasFTS reports the index as
		// usable. Searches then return zero hits and no error. The one-time
		// 'rebuild' below is what makes the index describe the table it indexes.
		legacyBodyIndex := db.ftsIndexesBody(ctx)
		ftsExisted := db.tableExists(ctx, "http_records_fts")

		if legacyBodyIndex {
			// Only drop the triggers when the table they write to is going away.
			// Dropping them on every seed would leave a window — however short —
			// in which concurrent inserts land in http_records and never reach
			// the index, permanently invisible to search.
			db.execBestEffort(ctx, "drop legacy FTS insert trigger", "DROP TRIGGER IF EXISTS http_records_fts_ai")
			db.execBestEffort(ctx, "drop legacy FTS delete trigger", "DROP TRIGGER IF EXISTS http_records_fts_ad")
			db.execBestEffort(ctx, "drop legacy FTS update trigger", "DROP TRIGGER IF EXISTS http_records_fts_au")
			db.execBestEffort(ctx, "drop legacy body-indexed FTS table", "DROP TABLE IF EXISTS http_records_fts")
		}

		_, ftsErr := db.ExecContext(ctx, `
			CREATE VIRTUAL TABLE IF NOT EXISTS http_records_fts USING fts5(
				url,
				path,
				hostname,
				content=http_records,
				content_rowid=rowid,
				tokenize='porter unicode61'
			)`)
		if ftsErr != nil {
			zap.L().Debug("FTS5 not available, falling back to CAST/LIKE searches", zap.Error(ftsErr))
			db.setFTS(false)
		} else {
			ftsTrigs := []string{
				`CREATE TRIGGER IF NOT EXISTS http_records_fts_ai AFTER INSERT ON http_records BEGIN
					INSERT INTO http_records_fts(rowid, url, path, hostname)
					VALUES (new.rowid, new.url, new.path, new.hostname);
				END`,
				`CREATE TRIGGER IF NOT EXISTS http_records_fts_ad AFTER DELETE ON http_records BEGIN
					INSERT INTO http_records_fts(http_records_fts, rowid, url, path, hostname)
					VALUES ('delete', old.rowid, old.url, old.path, old.hostname);
				END`,
				// The indexed columns are mutable — generic CRUD and the server's
				// record update can rewrite url/path/hostname — and without this
				// trigger the index kept the OLD tokens forever: searching the
				// value now stored found nothing, searching the value that was
				// replaced found the record. Delete-then-insert is the documented
				// way to restate a row in an external-content table.
				`CREATE TRIGGER IF NOT EXISTS http_records_fts_au
				 AFTER UPDATE OF url, path, hostname ON http_records BEGIN
					INSERT INTO http_records_fts(http_records_fts, rowid, url, path, hostname)
					VALUES ('delete', old.rowid, old.url, old.path, old.hostname);
					INSERT INTO http_records_fts(rowid, url, path, hostname)
					VALUES (new.rowid, new.url, new.path, new.hostname);
				END`,
			}
			triggersOK := true
			for _, trig := range ftsTrigs {
				if _, err := db.ExecContext(ctx, trig); err != nil {
					zap.L().Debug("Failed to create FTS trigger", zap.Error(err))
					triggersOK = false
				}
			}

			// Rebuild only on the transition — never on an already-current
			// database, where it would re-tokenize every row on every open and
			// make startup scale with corpus size.
			if triggersOK && (legacyBodyIndex || !ftsExisted) {
				db.rebuildFTSIfPopulated(ctx)
			}

			// The capability is published last, and only if the triggers that
			// keep it current are in place. Announcing a half-built index is how
			// a search returns nothing and looks like an answer.
			db.setFTS(triggersOK)
		}
	} else {
		// PostgreSQL: use tsvector with GIN index for full-text search.
		// to_tsvector rejects inputs over ~1 MiB, so cap the encoded raw
		// columns well under that to keep INSERT of large responses safe.
		_, pgErr := db.ExecContext(ctx, `
			ALTER TABLE http_records
			ADD COLUMN IF NOT EXISTS search_vector tsvector
			GENERATED ALWAYS AS (
				to_tsvector('english',
					coalesce(url, '') || ' ' ||
					coalesce(path, '') || ' ' ||
					coalesce(hostname, '') || ' ' ||
					coalesce(left(encode(raw_request, 'escape'), 524288), '') || ' ' ||
					coalesce(left(encode(raw_response, 'escape'), 524288), '')
				)
			) STORED`)
		if pgErr != nil {
			zap.L().Debug("PostgreSQL tsvector not available", zap.Error(pgErr))
		} else {
			db.execBestEffort(ctx, "create http_records search index",
				"CREATE INDEX IF NOT EXISTS idx_http_records_search ON http_records USING GIN (search_vector)")
			db.setFTS(true)
		}
	}

	return nil
}

// execBestEffort runs a best-effort migration or maintenance statement,
// logging (rather than propagating) any error. Used for idempotent backfills,
// legacy-index cleanup, and default seeding where a failure must not abort
// startup but should still be diagnosable.
func (db *DB) execBestEffort(ctx context.Context, op, query string, args ...any) {
	if _, err := db.ExecContext(ctx, query, args...); err != nil {
		zap.L().Debug("best-effort statement failed", zap.String("op", op), zap.Error(err))
	}
}

// addColumnIfNotExists attempts to add a column, ignoring errors if it already exists.
func (db *DB) addColumnIfNotExists(ctx context.Context, table, column, definition string) {
	ddl := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, definition)
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		// Ignore "duplicate column" errors (SQLite: "duplicate column name", Postgres: "already exists")
		errMsg := err.Error()
		if !strings.Contains(errMsg, "duplicate column") && !strings.Contains(errMsg, "already exists") {
			zap.L().Warn("Failed to add column", zap.String("column", column), zap.Error(err))
		}
	}
}

// projectUUIDMigrationTables are the tables that predate multi-tenancy and so
// need project_uuid added (and backfilled) on an existing database.
//
// Deliberately NARROWER than projectOwnedTables: analysis_artifacts,
// agentic_scans and authentication_hostnames are project-scoped too, but they
// were created with the column in their own CREATE TABLE, so they need neither
// the ALTER nor the O(rows) backfill. Widening this to projectOwnedTables would
// add a full-table UPDATE per open for three tables that cannot need it.
var projectUUIDMigrationTables = []string{
	"scans", "http_records", "findings", "scopes", "oast_interactions", "scan_logs",
}

// runColumnMigrations applies every additive column migration. It is the SINGLE
// list of columns this binary expects on an existing database — CreateSchema
// calls it to apply them, and checkSchemaCurrent calls it in dry-run mode to
// report the ones a read-only handle is missing. Keeping one list is what stops
// the read-only check from drifting into a stale copy that passes a database the
// queries then fail on.
// columnMigration is one additive column an existing database may be missing.
type columnMigration struct{ Table, Column, Def string }

// columnMigrations is the SINGLE list of columns this binary expects on an
// existing database. Data rather than a sequence of method calls, because it has
// two consumers that must never disagree: CreateSchema APPLIES it, and
// missingColumns ASKS it. Expressing "ask instead of apply" as a mode flag on
// the mutating method meant a field on the shared *DB handle that silently
// turned every addColumn into a no-op for whoever else held that handle.
//
// Notes that used to sit on individual calls:
//   - surface_score is separate from risk_score deliberately: risk_score holds
//     anomaly_ranking's batch percentile, a different scale from different
//     inputs, and one column cannot carry both without the later writer silently
//     erasing the other. DEFAULT 0 reads as "no surface signals", the correct
//     floor for every row that predates the column.
//   - The project_uuid entries are appended at init from
//     projectUUIDMigrationTables, which is narrower than projectOwnedTables: the
//     newer project-scoped tables declare the column in their own CREATE TABLE
//     and need neither the ALTER nor the O(rows) backfill.
var columnMigrations = []columnMigration{
	{"findings", "request", "TEXT"},
	{"findings", "response", "TEXT"},
	{"http_records", "request_authorization", "TEXT"},
	{"http_records", "response_title", "TEXT"},
	{"http_records", "response_words", "INTEGER DEFAULT 0"},
	{"http_records", "response_norm_hash", "TEXT"},
	{"http_records", "response_location", "TEXT"},
	{"http_records", "source", "TEXT DEFAULT ''"},
	{"http_records", "remarks", "TEXT"},
	{"http_records", "risk_score", "INTEGER DEFAULT 0"},
	{"http_records", "surface_score", "INTEGER DEFAULT 0"},
	{"findings", "confidence", "TEXT NOT NULL DEFAULT 'firm'"},
	{"findings", "scan_uuid", "TEXT"},
	{"findings", "module_type", "TEXT DEFAULT ''"},
	{"findings", "finding_source", "TEXT DEFAULT ''"},
	{"findings", "record_kind", "TEXT NOT NULL DEFAULT 'finding'"},
	{"findings", "evidence_grade", "TEXT DEFAULT ''"},
	{"findings", "module_short", "TEXT DEFAULT ''"},
	{"scans", "scan_source", "TEXT"},
	{"scans", "scan_mode", "TEXT"},
	{"scans", "start_cursor_at", "TIMESTAMP"},
	{"scans", "start_cursor_uuid", "TEXT"},
	{"scans", "cursor_at", "TIMESTAMP"},
	{"scans", "cursor_uuid", "TEXT"},
	{"scans", "processed_count", "INTEGER DEFAULT 0"},
	{"agentic_scans", "session_id", "TEXT"},
	{"projects", "tags", "TEXT"},
	{"projects", "default_target", "TEXT"},
	{"projects", "last_scan_at", "TIMESTAMP"},
	{"scans", "profile", "TEXT"},
	{"scans", "source_path", "TEXT"},
	{"scans", "source_type", "TEXT"},
	{"scans", "http_record_uuid", "TEXT"},
	{"scans", "tags", "TEXT"},
	{"scans", "triggered_by", "TEXT"},
	{"scans", "agentic_scan_uuid", "TEXT"},
	{"http_records", "scan_uuid", "TEXT"},
	{"http_records", "technology", "TEXT"},
	{"http_records", "content_hash", "TEXT"},
	{"http_records", "is_authenticated", "INTEGER NOT NULL DEFAULT 0"},
	{"http_records", "parent_uuid", "TEXT"},
	{"findings", "agentic_scan_uuid", "TEXT"},
	{"findings", "url", "TEXT"},
	{"findings", "hostname", "TEXT"},
	{"findings", "status", "TEXT DEFAULT 'triaged'"},
	{"findings", "remediation", "TEXT"},
	{"findings", "cwe_id", "TEXT"},
	{"findings", "cvss_score", "REAL DEFAULT 0"},
	{"findings", "source_file", "TEXT"},
	{"findings", "repo_name", "TEXT"},
	{"agentic_scans", "source_path", "TEXT"},
	{"agentic_scans", "token_usage", "TEXT"},
	{"agentic_scans", "retry_count", "INTEGER DEFAULT 0"},
	{"agentic_scans", "parent_run_uuid", "TEXT"},
	{"agentic_scans", "input_record_count", "INTEGER DEFAULT 0"},
	{"agentic_scans", "session_dir", "TEXT"},
	{"agentic_scans", "protocol", "TEXT"},
	{"agentic_scans", "model", "TEXT"},
	{"agentic_scans", "total_input_tokens", "INTEGER NOT NULL DEFAULT 0"},
	{"agentic_scans", "total_output_tokens", "INTEGER NOT NULL DEFAULT 0"},
	{"agentic_scans", "estimated_cost_usd", "REAL NOT NULL DEFAULT 0"},
	{"scans", "storage_url", "TEXT"},
	{"agentic_scans", "storage_url", "TEXT"},
	{"oast_interactions", "finding_id", "INTEGER"},
	{"oast_interactions", "payload", "TEXT"},
	{"scopes", "content_type_pattern", "TEXT"},
	{"scopes", "hit_count", "INTEGER DEFAULT 0"},
	{"scopes", "last_matched_at", "TIMESTAMP"},
	{"authentication_hostnames", "session_token", "TEXT"},
	{"authentication_hostnames", "hydrated_at", "TIMESTAMP"},
}

func init() {
	for _, table := range projectUUIDMigrationTables {
		columnMigrations = append(columnMigrations, columnMigration{
			Table: table, Column: "project_uuid",
			Def: fmt.Sprintf("TEXT NOT NULL DEFAULT '%s'", DefaultProjectUUID),
		})
	}
}

// runColumnMigrations applies every additive column migration.
func (db *DB) runColumnMigrations(ctx context.Context) {
	for _, m := range columnMigrations {
		db.addColumnIfNotExists(ctx, m.Table, m.Column, m.Def)
	}
}

// ErrSchemaOutdated marks a database written by an older vigolium that this
// handle cannot migrate because it was opened read-only. It is a distinct error
// because it is FATAL to the command — every query that follows would fail on a
// missing column — whereas a migration failure on a writable handle is
// best-effort and worth only a warning.
var ErrSchemaOutdated = errors.New("database schema is older than this vigolium and --read-only cannot migrate it")

// EnsureSchemaCurrent brings an existing database up to date, doing NOTHING when
// it already is.
//
// The "do nothing" path is the whole point. CreateSchema issues DDL, and DDL
// takes SQLite's WRITE lock — so calling it unconditionally on every open makes
// every read command queue behind any concurrent writer for up to busy_timeout
// (60s by default). Detecting staleness first is a read-only question, so the
// common case takes no lock at all.
//
// A read-only handle cannot be migrated (mode=ro refuses DDL); CreateSchema's
// own read-only branch turns that into ErrSchemaOutdated naming the missing
// columns, so it is reached through the same call rather than special-cased
// here.
//
// Indexes are deliberately not part of the check: they are a performance
// concern, not a correctness one, and the write commands still call CreateSchema
// directly. Only a missing TABLE or COLUMN can make a query fail outright.
func (db *DB) EnsureSchemaCurrent(ctx context.Context) error {
	missing, err := db.missingColumns(ctx)
	if err == nil && len(missing) == 0 {
		return nil
	}
	return db.CreateSchema(ctx)
}

// HasVigoliumSchema reports whether this store has been initialized as a
// vigolium database, by the presence of the core table every read touches.
//
// It is the question "is this the right file?", which is NOT the same as "does
// it have rows": a foreign SQLite file and a scanned target both open cleanly,
// and only this distinguishes them before vigolium's tables get created inside
// the former.
func (db *DB) HasVigoliumSchema(ctx context.Context) bool {
	return db.tableExists(ctx, "http_records")
}

// checkSchemaCurrent reports a read-only handle's missing columns as an error
// naming them and how to proceed, or nil when it is current.
//
// Without it the caller's first SELECT fails with a bare "no such column:
// r.surface_score" — a symptom naming no remedy. A brand-new/empty file is not
// "outdated": it has no tables at all, and every read of it correctly returns
// nothing.
func (db *DB) checkSchemaCurrent(ctx context.Context) error {
	missing, err := db.missingColumns(ctx)
	if err != nil || len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("%w (missing: %s)\n"+
		"  drop --read-only to upgrade it in place, or copy the file first if it must not change",
		ErrSchemaOutdated, strings.Join(missing, ", "))
}

// missingColumns reports which entries of columnMigrations this database lacks,
// as "table.column". Read-only: it never takes a write lock.
//
// One catalog query PER TABLE, not one existence probe per column. There are ~75
// migrated columns across 8 tables, so probing each individually cost ~75 round
// trips on every process start — negligible on SQLite, but ~75 network RTTs on a
// Postgres deployment, paid by every CLI invocation.
//
// A returned error means the catalog could not be read at all (an empty or
// unopenable file); callers treat that as "cannot tell" rather than as "stale",
// since a fresh database legitimately has no tables yet.
func (db *DB) missingColumns(ctx context.Context) ([]string, error) {
	// An absent core table means a fresh (or empty) file: it needs the full
	// CreateSchema, and being new it has no concurrent writer to contend with.
	if !db.tableExists(ctx, "http_records") {
		return nil, errSchemaNotInitialized
	}

	existing := make(map[string]map[string]bool)
	var missing []string
	for _, m := range columnMigrations {
		cols, ok := existing[m.Table]
		if !ok {
			cols = make(map[string]bool)
			// A table that does not exist yet reports no columns, so every one of
			// its migrations lands in `missing` and CreateSchema creates it.
			if infos, err := ListColumns(ctx, db, m.Table); err == nil {
				for _, info := range infos {
					cols[info.Name] = true
				}
			}
			existing[m.Table] = cols
		}
		if !cols[m.Column] {
			missing = append(missing, m.Table+"."+m.Column)
		}
	}
	return missing, nil
}

// errSchemaNotInitialized marks a database with no core table — a fresh file,
// not a stale one.
var errSchemaNotInitialized = errors.New("schema not initialized")

// tableExists reports whether a table is present.
func (db *DB) tableExists(ctx context.Context, table string) bool {
	var n int
	err := db.QueryRowContext(ctx,
		fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE 1=0", table)).Scan(&n)
	return err == nil
}

// expandPath handles ~ expansion and environment variables
func expandPath(path string) string {
	// Expand environment variables
	path = expandEnvVars(path)

	// Expand ~ to home directory
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		path = filepath.Join(home, path[2:])
	}

	return path
}

// expandEnvVars replaces ${VAR} or $VAR with environment variable values
func expandEnvVars(s string) string {
	return os.ExpandEnv(s)
}

// debugQueryHook logs SQL queries in debug mode
type debugQueryHook struct{}

func (h debugQueryHook) BeforeQuery(ctx context.Context, event *bun.QueryEvent) context.Context {
	return ctx
}

func (h debugQueryHook) AfterQuery(ctx context.Context, event *bun.QueryEvent) {
	query := event.Query
	// Skip logging DDL statements and noisy internal queries to reduce noise
	if strings.HasPrefix(query, "CREATE ") || strings.HasPrefix(query, "ALTER ") ||
		strings.Contains(query, "finding_records") {
		return
	}
	if len(query) > 500 {
		query = query[:500] + "..."
	}
	zap.L().Debug("SQL query executed",
		zap.String("query", query),
		zap.Duration("duration", time.Since(event.StartTime)),
	)
}
