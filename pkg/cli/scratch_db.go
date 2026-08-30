package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

// scratchDBDir is the temp directory holding the throwaway database a --glob-db
// merge (or a stateless JSONL load) was built in, so closeDatabaseOnExit can
// remove it. Not guarded: every command builds and closes its scratch database
// on its own goroutine, and RunWithWatch loops the command body in place rather
// than spawning one per tick.
var scratchDBDir string

// newTempDB creates a throwaway database backed by a temp FILE, returning it
// ready for CreateSchema alongside the directory holding it — whoever disposes
// of the handle removes that directory.
//
// The file matters. A throwaway database assembled in ":memory:" is anonymous
// heap: it cannot be evicted, so it competes with the process's own allocations
// and collapses into swap once the source outgrows RAM — measured at 18.7 GB RSS
// and 149 seconds of kernel paging on a 36 GB machine, for an 854-file / 16 GB
// glob export that never finished. On a file the same working set is paged
// against the OS page cache, which evicts cleanly under pressure, and anything
// small enough to fit in RAM simply stays in cache — so nothing is given up at
// the small end.
//
// Two pragmas differ from the normal database defaults, and the two that do NOT
// differ are the load-bearing ones:
//
//   - synchronous=OFF and journal_mode=MEMORY. The file is disposable, so there
//     is nothing to protect against a power loss, and those two costs are what
//     dominate a bulk load of this size — WAL would write the whole corpus twice
//     (once to the -wal, once at checkpoint) and, at the default 1000-page
//     autocheckpoint, drain it in ~4000 passes.
//   - journal_mode is MEMORY rather than OFF because mergeOnce runs each file's
//     copy in a transaction with a deferred Rollback, and rollback without a
//     journal is undefined — one failed merge could corrupt the whole set. A
//     rollback journal costs concurrent reader/writer access, which nothing here
//     needs: the merge is a single writer, and every later use is read-only.
//   - MaxOpenConns stays at the default. Not 1: ":memory:" is pinned to one
//     connection because each connection there gets its OWN database, which is a
//     constraint of in-memory SQLite rather than something callers were written
//     against. `export` streams rows while issuing further queries and deadlocks
//     outright against a single connection.
func newTempDB(label string) (*database.DB, string, error) {
	dir, err := os.MkdirTemp("", scratchDBPrefix+label+"-")
	if err != nil {
		return nil, "", fmt.Errorf("create scratch directory: %w", err)
	}

	cfg := config.DefaultDatabaseConfig()
	cfg.Driver = "sqlite"
	cfg.SQLite.Path = filepath.Join(dir, label+".sqlite")
	cfg.SQLite.Synchronous = "OFF"
	cfg.SQLite.JournalMode = "MEMORY"

	db, err := database.NewDB(cfg)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, "", fmt.Errorf("failed to create scratch database: %w", err)
	}
	return db, dir, nil
}

// newScratchDB is newTempDB for the one throwaway database a command keeps for
// its whole run — the --glob-db merge, or a stateless JSONL load. That database
// outlives its constructor inside the shared connection cache, so its directory
// is recorded for closeDatabaseOnExit to remove rather than handed back. A caller
// that disposes of its own database (openGlobSourceFile, which opens one per
// source file) uses newTempDB directly.
func newScratchDB(label string) (*database.DB, error) {
	reapStaleScratchDBs()

	db, dir, err := newTempDB(label)
	if err != nil {
		return nil, err
	}

	// Replace rather than append: a command builds at most one scratch database,
	// and leaving an earlier path unremoved would leak it for the process's life.
	removeScratchDB()
	scratchDBDir = dir
	return db, nil
}

// scratchDBPrefix names every temp directory newTempDB creates, so the reaper
// can recognise its own leftovers and nothing else.
const scratchDBPrefix = "vigolium-scratch-"

// scratchDBMaxAge is how long a scratch directory may sit before the reaper
// treats it as abandoned. It only has to exceed the runtime of a real merge —
// an 854-file, 16 GB glob takes minutes — while staying far below the point at
// which a stranded copy of a whole engagement's traffic becomes a problem.
const scratchDBMaxAge = 6 * time.Hour

// reapStaleScratchDBs removes scratch directories left behind by runs that never
// got to close theirs.
//
// This is not housekeeping: closeDatabaseOnExit only runs on a normal return, so
// a Ctrl-C, an OOM kill, or a SIGKILL during a large merge strands the whole
// scratch database — on this workload 15 GB apiece, and they accumulate silently
// because nothing else ever looks in that directory. Reaping on creation means
// the next run pays the cleanup, which is the only moment we know one is safe to
// take: a directory older than scratchDBMaxAge cannot belong to a live merge.
//
// Age, rather than liveness of an owning pid, because a pid check that is wrong
// on some platform deletes a running merge's database out from under it — the
// failure is silent corruption, where the failure of an over-long age window is
// only a delayed cleanup.
func reapStaleScratchDBs() {
	root := os.TempDir()
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-scratchDBMaxAge)
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), scratchDBPrefix) {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		_ = os.RemoveAll(filepath.Join(root, entry.Name()))
	}
}

// removeScratchDB deletes the scratch database directory, if one was created.
// Safe to call when there is none, and safe to call twice.
func removeScratchDB() {
	dir := scratchDBDir
	scratchDBDir = ""
	if dir != "" {
		_ = os.RemoveAll(dir)
	}
}
