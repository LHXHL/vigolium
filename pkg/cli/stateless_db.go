package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dbimport"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// globalGlobDB is the --glob-db flag: a glob pattern of local result files
// (.sqlite/.jsonl exports, audit folders, archives) that are merged into one
// throwaway in-memory DB and read with project scoping off. Registered on the
// read/query commands (finding, traffic, export) and on import. Providing it
// implies stateless-read semantics, so -S is optional alongside it.
var globalGlobDB string

// globDBSources records what each --glob-db source file contributed to the
// merged in-memory DB, captured in match order by openGlobDB. The findings merge
// assigns fresh sequential autoincrement ids per file, so a finding whose id
// falls in a file's (findingLo, findingHi] range came from that file — which lets
// the finding tree show one db-path root per source file so an analyst sees
// where each finding originated. Empty when not reading through --glob-db.
var globDBSources []globDBSource

// globRecordFile maps an http_record uuid to the --glob-db file it came from.
// http_records are keyed by uuid with no exposed integer id, so the traffic tree
// can't attribute records by id range like findings; instead openGlobDB builds
// this map during the merge (from each file's fresh rowid range). Empty when not
// reading through --glob-db.
var globRecordFile map[string]string

// globDBSkipped is the skip set the merge actually ran with, recorded by
// openGlobDB alongside globDBSources and globRecordFile. Anything that needs a
// record the merge may have left out asks globMergeOmittedRecords() rather than
// re-deriving the answer from the flags: the merge is what decided, so a second
// derivation elsewhere is one that can disagree — and the symptom of disagreeing
// is silently empty request/response bytes, not an error.
var globDBSkipped globDBSkipSet

// globMergeOmittedRecords reports whether a --glob-db merge ran and left record
// rows or bodies out of the result, so evidence has to be fetched from the source
// files instead (loadGlobFindingRecords). False for a single --db source, which
// is queried in place with nothing omitted.
func globMergeOmittedRecords() bool {
	return len(globDBSources) > 0 && (globDBSkipped.Records || globDBSkipped.RecordBodies)
}

// globDBSkipSet lets a read command tell openGlobDB which parts of the merge it
// will never read, so they can be skipped. Every field is a negative opt-in and
// the zero value merges everything, so a command that passes nothing — or a new
// one that doesn't know about this — stays correct.
//
// This exists because openGlobDB merges into an *in-memory* SQLite before the
// first WHERE runs, so anything copied is paid for in RAM. Over a large glob
// (a few hundred result files is ~10 GB, ~98% of it raw request/response blobs)
// an unskipped merge exceeds physical memory and collapses into swap, which
// costs minutes of kernel time rather than seconds of work.
//
// Each field is only safe when nothing downstream reads what it drops, and the
// failure mode is silent wrong output rather than an error — so build one from an
// explicit per-command predicate (findingNeedsRecords, trafficRendersRawBodies)
// rather than ad hoc at a call site.
type globDBSkipSet struct {
	// Records omits the http_records table entirely. Safe only for a reader that
	// never resolves a finding's linked records: findings embed their own
	// request/response inline and finding_records has no foreign key into
	// http_records, so findings and the junction still merge intact.
	Records bool

	// RecordBodies keeps every http_records row but omits its
	// raw_request/raw_response columns (~96% of the table's bytes, and nullable).
	// Because rows are kept, counts and metadata predicates are unaffected. Unsafe
	// for anything that prints the raw corpus or filters over it in SQL, where the
	// absent columns make LIKE match nothing (see QueryFilters.UsesRawCorpus).
	// Ignored when Records is set.
	RecordBodies bool

	// RecordFileMap omits the record-uuid → source-file map, whose only consumer
	// is the traffic tree's per-file root labels (globSourceForRecord). Building
	// it re-scans every merged record and holds an entry per row, so a reader that
	// isn't the traffic tree should skip it. See skipRecordFileMap for how Records
	// implies this.
	RecordFileMap bool
}

// skipRecordFileMap reports whether the record→file map should be left unbuilt.
// Skipping the records themselves implies it: there would be nothing to map.
func (s globDBSkipSet) skipRecordFileMap() bool {
	return s.Records || s.RecordFileMap
}

// expandUserHome resolves a leading ~ (bare, or "~/…") in a path or glob pattern
// to the current user's home directory, leaving everything else byte-for-byte
// intact so glob metacharacters survive.
//
// It matters most for --glob-db: the pattern has to be single-quoted to keep the
// shell from expanding the glob itself, which also suppresses the shell's tilde
// expansion — so '~/scans/*.sqlite' arrives here literally, and filepath.Glob
// has no notion of ~ and would match nothing. ~user is not resolved.
func expandUserHome(p string) string {
	if p != "~" && !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return p
	}
	if p == "~" {
		return home
	}
	return filepath.Join(home, p[2:])
}

// globDBMatches expands a --glob-db pattern to the local files it names. Shared
// by every consumer of the flag so one wording of "no such pattern" / "matched
// nothing" reaches the user regardless of which command asked.
func globDBMatches(pattern string) ([]string, error) {
	matches, err := filepath.Glob(expandUserHome(pattern))
	if err != nil {
		return nil, fmt.Errorf("invalid --glob-db pattern %q: %w", pattern, err)
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("--glob-db %q matched no files", pattern)
	}
	return matches, nil
}

// openGlobSourceFile opens one --glob-db match as a queryable database, for the
// paths that read matches one at a time rather than merging them: the streaming
// Burp copy (saveGlobToBurp) and the lazy finding-evidence hydration
// (loadGlobFindingRecords). The returned closer disposes of the handle and of
// any temp file behind it.
//
// A plain SQLite result file is queried in place, with no copy, so the memory
// cost is the result set rather than the file. Anything else a glob can match (a
// JSONL export, an archive, an audit folder) has no queryable form on disk and is
// loaded through the same importer the merged path uses — into a temp file for
// the same reason the merge uses one, since a single source can be large enough
// to matter on its own.
//
// It deliberately does not go through clicommon.GetDB: that caches one connection
// process-wide, so the second file — and every file after it — would silently be
// answered by the first.
func openGlobSourceFile(ctx context.Context, path string) (*database.DB, func(), error) {
	if isSQLite, err := database.IsSQLiteFile(path); err == nil && isSQLite {
		cfg := config.DefaultDatabaseConfig()
		cfg.Driver = "sqlite"
		cfg.SQLite.Path = path
		db, err := database.NewDB(cfg)
		if err != nil {
			return nil, nil, err
		}
		return db, func() { _ = db.Close() }, nil
	}

	db, dir, err := newTempDB("source")
	if err != nil {
		return nil, nil, err
	}
	closeDB := func() {
		_ = db.Close()
		_ = os.RemoveAll(dir)
	}
	if err := db.CreateSchema(ctx); err != nil {
		closeDB()
		return nil, nil, fmt.Errorf("initialize scratch schema: %w", err)
	}
	if _, err := dbimport.ImportPath(ctx, database.NewRepository(db), path, "", dbimport.Options{}); err != nil {
		closeDB()
		return nil, nil, err
	}
	return db, closeDB, nil
}

// globDBSource is one --glob-db file and the findings id range it added.
type globDBSource struct {
	file      string
	findingLo int64 // findings with id in (findingLo, findingHi] came from this file
	findingHi int64
}

// globDBMergedCount reports how many files openGlobDB merged.
func globDBMergedCount() int { return len(globDBSources) }

// globSourceForFinding returns the source file a merged finding id came from, or
// "" if it can't be attributed (single-DB read, or a deduped row).
func globSourceForFinding(id int64) string {
	for _, s := range globDBSources {
		if id > s.findingLo && id <= s.findingHi {
			return s.file
		}
	}
	return ""
}

// globSourceForRecord returns the source file a merged http_record uuid came
// from, or "" when not attributable (single-DB read, or a deduped row).
func globSourceForRecord(uuid string) string { return globRecordFile[uuid] }

// maxRowID returns the current MAX(col) of a table (0 when empty), used to
// snapshot per-file id/rowid ranges around each glob merge. col is a fixed
// literal ("id"/"rowid"), not user input.
func maxRowID(ctx context.Context, db *database.DB, table, col string) int64 {
	var id int64
	_ = db.SQLDB().QueryRowContext(ctx, fmt.Sprintf("SELECT COALESCE(MAX(%s), 0) FROM %s", col, table)).Scan(&id)
	return id
}

// mapRecordsToFile records that every http_record inserted after afterRowid
// (i.e. by the file just merged, since no later file has run yet) came from file.
func mapRecordsToFile(ctx context.Context, db *database.DB, afterRowid int64, file string) {
	rows, err := db.SQLDB().QueryContext(ctx, "SELECT uuid FROM http_records WHERE rowid > ?", afterRowid)
	if err != nil {
		return
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var uuid string
		if rows.Scan(&uuid) == nil {
			globRecordFile[uuid] = file
		}
	}
}

// statelessReadRequested reports whether a read/query command should source its
// data from a standalone file rather than the shared project DB — true under
// -S/--stateless, whenever --glob-db is set (which implies stateless), or when
// $VIGOLIUM_DB_PATH pinned the shell to a session database.
//
// Every read path funnels through here (openReadDB, openExportDB,
// effectiveProjectUUID), which is why the env var implies its read semantics
// here rather than by enumerating command names: a command is covered the
// moment it asks this question, including ones that never register -S at all
// (`fuzz -u <uuid>` resolves a record through effectiveProjectUUID).
func statelessReadRequested() bool {
	return globalStateless || strings.TrimSpace(globalGlobDB) != "" || dbPathEnvAutoStateless
}

// statelessSourceError reports why path cannot back a stateless read, or nil
// when it can. openStatelessDB surfaces the error; applyDBPathEnv only needs the
// yes/no (statelessSourceUsable) to decide whether to imply a stateless read at
// all. Both read the same rule, so the gate can't drift from the opener whose
// outcome it exists to predict.
func statelessSourceError(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("--db %q: %w", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("--db %q is a directory; expected a .jsonl export or .sqlite file", path)
	}
	return nil
}

// statelessSourceUsable reports whether path can back a stateless read.
func statelessSourceUsable(path string) bool { return statelessSourceError(path) == nil }

// openReadDB returns the database for read/query commands (traffic, finding).
// Under -S/--stateless (or --glob-db) it reads from the --db source directly (a
// JSONL export or a standalone SQLite file) or the merged --glob-db set;
// otherwise it returns the shared project DB.
//
// skip narrows what a --glob-db merge copies; pass the zero globDBSkipSet to
// merge everything (it is ignored unless --glob-db is set).
func openReadDB(skip globDBSkipSet) (*database.DB, error) {
	if statelessReadRequested() {
		return openStatelessDB(skip)
	}
	return getDB()
}

// displayDBPath returns a human-readable label for the database currently being
// read, used as the root node of the traffic/finding --tree views. It reflects
// the resolved source in precedence order: a --glob-db pattern, an explicit --db
// path, otherwise the configured default SQLite path (home shortened to ~).
func displayDBPath() string {
	raw := config.DefaultDatabaseConfig().SQLite.Path
	switch {
	case strings.TrimSpace(globalGlobDB) != "":
		// A glob is a pattern, not a single file — make the merged nature explicit.
		pattern := strings.TrimSpace(globalGlobDB)
		if n := globDBMergedCount(); n > 0 {
			return fmt.Sprintf("%s (%d databases merged)", terminal.ShortenHome(pattern), n)
		}
		raw = pattern
	case strings.TrimSpace(globalDB) != "":
		raw = strings.TrimSpace(globalDB)
	default:
		if settings, err := config.LoadSettings(globalConfig); err == nil {
			if p := strings.TrimSpace(settings.Database.SQLite.Path); p != "" {
				raw = p
			}
		}
	}
	return terminal.ShortenHome(raw)
}

// effectiveProjectUUID is the project filter for read/query commands: empty (no
// scoping, show every row) under -S/--stateless or --glob-db since a standalone
// file carries its own foreign project_uuid, otherwise the active project.
func effectiveProjectUUID() (string, error) {
	if statelessReadRequested() {
		return "", nil
	}
	return resolveProjectUUID()
}

// openStatelessDB resolves the -S/--stateless data source named by --db. The
// source may be either:
//
//   - a standalone .sqlite file — opened directly (read-only intent), or
//   - a {"type":...,"data":{...}} JSONL export (e.g. from
//     `vigolium scan --format jsonl`) — loaded into a throwaway in-memory
//     SQLite so every existing filter / sort / display path runs unchanged.
//
// Callers query with ProjectUUID="" (project scoping off), so all rows in the
// file are shown regardless of the project_uuid they were exported under.
func openStatelessDB(skip globDBSkipSet) (*database.DB, error) {
	// --glob-db expands to many files merged into one in-memory DB; it takes
	// precedence over a single --db source.
	if pattern := strings.TrimSpace(globalGlobDB); pattern != "" {
		return openGlobDB(pattern, skip)
	}
	if strings.TrimSpace(globalDB) == "" {
		return nil, fmt.Errorf("--stateless requires --db <file.jsonl|file.sqlite> or --glob-db <pattern>")
	}
	path := globalDB
	if err := statelessSourceError(path); err != nil {
		return nil, err
	}

	if isJSONLSource(path) {
		return loadStatelessJSONL(path)
	}
	// Standalone SQLite: open directly via the shared connection cache (honours
	// --config); --db already points the cache at this file.
	return clicommon.GetDB(globalConfig, path)
}

// loadStatelessJSONL parses a {type,data} JSONL export into a fresh in-memory
// SQLite and returns it. The finding↔record linkage is preserved by the
// importer, so finding --raw / --with-records resolves linked records too.
func loadStatelessJSONL(path string) (*database.DB, error) {
	ctx := context.Background()

	db, err := newScratchDB("stateless")
	if err != nil {
		return nil, err
	}
	if err := db.CreateSchema(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialize scratch schema: %w", err)
	}

	f, err := os.Open(path)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to open --db %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	// projectUUID "" → rows import under the default project; the callers query
	// with ProjectUUID="" (no project filter) so everything in the file shows.
	res, err := dbimport.ImportJSONL(ctx, database.NewRepository(db), f, "", dbimport.Options{})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to load JSONL from %q: %w", path, err)
	}

	fmt.Fprintf(os.Stderr, "%s Stateless: loaded %d HTTP record(s) and %d finding(s) from %s\n",
		terminal.InfoSymbol(), res.RecordsImported, res.FindingsTotal, terminal.Cyan(filepath.Base(path)))

	// Cache it so the rest of the command (and closeDatabaseOnExit) reuse and
	// close this connection rather than opening the default project DB.
	clicommon.SetDBCache(db)
	return db, nil
}

// openGlobDB expands pattern to local result files and merges them all into a
// single throwaway in-memory SQLite DB, which callers query with project
// scoping off. Each match is imported by its own detected type via
// dbimport.ImportPath (SQLite→SQLite merge, JSONL export, audit folder, or
// archive), so a glob can mix formats. A match that fails to import is skipped
// with a warning rather than aborting the whole read. Returns an error when the
// pattern is invalid, matches nothing, or nothing could be loaded.
func openGlobDB(pattern string, skip globDBSkipSet) (*database.DB, error) {
	matches, err := globDBMatches(pattern)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	db, err := newScratchDB("glob")
	if err != nil {
		return nil, err
	}
	if err := db.CreateSchema(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialize scratch schema: %w", err)
	}
	repo := database.NewRepository(db)

	// projectUUID "" → SQLite merges keep each row's original project and JSONL
	// rows import under the default project; callers query with ProjectUUID=""
	// (no project filter) so everything in every matched file shows.
	globDBSources = nil
	globDBSkipped = skip
	globRecordFile = make(map[string]string)
	var loaded, totalRecords, totalFindings int
	for _, m := range matches {
		// Snapshot the findings id / http_records rowid high-water marks before
		// each file so the rows it adds (fresh sequential ids/rowids, since no
		// later file has run yet) can be attributed back to it.
		fLo := maxRowID(ctx, db, "findings", "id")
		trackFiles := !skip.skipRecordFileMap()
		var rLo int64
		if trackFiles {
			rLo = maxRowID(ctx, db, "http_records", "rowid")
		}
		res, impErr := dbimport.ImportPath(ctx, repo, m, "", dbimport.Options{
			SkipHTTPRecords:  skip.Records,
			SkipRecordBodies: skip.RecordBodies,
		})
		if impErr != nil {
			fmt.Fprintf(os.Stderr, "%s --glob-db: skipped %s: %v\n", terminal.WarningSymbol(), terminal.Cyan(m), impErr)
			continue
		}
		globDBSources = append(globDBSources, globDBSource{
			file:      m,
			findingLo: fLo,
			findingHi: maxRowID(ctx, db, "findings", "id"),
		})
		if trackFiles {
			mapRecordsToFile(ctx, db, rLo, m)
		}
		loaded++
		totalRecords += res.RecordsImported
		totalFindings += res.FindingsTotal
	}
	if loaded == 0 {
		_ = db.Close()
		return nil, fmt.Errorf("--glob-db %q: none of the %d matched file(s) could be loaded", pattern, len(matches))
	}

	// With the record copy skipped totalRecords is 0 — report findings alone
	// rather than claiming the source files held no traffic.
	counts := fmt.Sprintf("%d finding(s)", totalFindings)
	if !skip.Records {
		counts = fmt.Sprintf("%d HTTP record(s), %s", totalRecords, counts)
	}
	fmt.Fprintf(os.Stderr, "%s Stateless: merged %d file(s) — %s — from %s\n",
		terminal.InfoSymbol(), loaded, counts, terminal.Cyan(pattern))

	// Cache it so the rest of the command (and closeDatabaseOnExit) reuse and
	// close this connection rather than opening the default project DB.
	clicommon.SetDBCache(db)
	return db, nil
}

// openExportDB returns the database for `vigolium export`. It honors --glob-db
// (merge a glob of result files) and -S/--stateless (a single standalone --db
// source) so the export commands can read from ad-hoc files, falling back to the
// shared project DB. Export already reads whole-DB (project scoping off), so a
// standalone source needs no further project handling.
func openExportDB() (*database.DB, error) {
	if statelessReadRequested() {
		// Export streams whole records, bodies included, so it merges everything.
		return openStatelessDB(globDBSkipSet{})
	}
	return getDB()
}

// isJSONLSource decides whether --db points at a JSONL export (true) or a
// SQLite database (false). It trusts a known extension, otherwise sniffs the
// file header: SQLite files begin with the magic string "SQLite format 3\0",
// while a JSONL export begins with '{'.
func isJSONLSource(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".jsonl", ".ndjson":
		return true
	case ".sqlite", ".sqlite3", ".db":
		return false
	}

	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, 16)
	n, _ := f.Read(buf)
	head := buf[:n]
	if database.HasSQLiteHeader(head) {
		return false
	}
	// First non-whitespace byte: '{' marks a JSON envelope line.
	trimmed := bytes.TrimLeft(head, " \t\r\n")
	return len(trimmed) > 0 && trimmed[0] == '{'
}
