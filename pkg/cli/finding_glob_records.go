package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// loadGlobFindingRecords resolves the HTTP records a page of findings links to by
// reading the --glob-db source files one at a time, instead of from the merged
// database.
//
// The merge cannot carry them. --raw/--markdown/--with-records/--push-to-burp
// want the raw request/response of the handful of findings on screen, but the
// merged database is built before the first WHERE runs, so honouring that meant
// copying every matched file's ENTIRE record corpus into memory — 20.4 GB and 206
// seconds of kernel paging on an 854-file glob, to hydrate a hundred findings.
// Fetching afterwards inverts it: the merge stays findings-only (~2 s), and the
// records are pulled by uuid, which is an indexed primary-key lookup.
//
// Files are visited in the order the findings themselves came from, because
// globDBSources already attributes each merged finding id to its source file — so
// a page of findings normally touches a handful of files rather than all of them.
// Any uuid left unresolved by that pass falls back to a sweep of the remaining
// files: the attribution is a strong hint (a per-host result database holds a
// finding and its evidence together), not a guarantee that must hold for the
// output to be correct.
func loadGlobFindingRecords(
	ctx context.Context,
	findings []*database.Finding,
	uuids []string,
) map[string]*database.HTTPRecord {
	if len(uuids) == 0 {
		return nil
	}

	fetch := globRecordFetch{
		wanted: make(map[string]struct{}, len(uuids)),
		byUUID: make(map[string]*database.HTTPRecord, len(uuids)),
	}
	for _, uuid := range uuids {
		fetch.wanted[uuid] = struct{}{}
	}
	started := time.Now()

	order, byFile := globFindingRecordPlan(findings, fetch.wanted)
	fmt.Fprintf(os.Stderr, "%s Resolving %d linked HTTP record(s) from %d source file(s)\n",
		terminal.InfoSymbol(), len(fetch.wanted), len(order))
	for _, file := range order {
		fetch.from(ctx, file, byFile[file])
	}

	// Anything still missing was linked by a finding whose own file did not hold
	// it (or by a finding that could not be attributed at all, e.g. a row deduped
	// away during the merge). Sweep whatever is left rather than silently
	// rendering it as empty evidence. Passing nil asks each file for everything
	// still outstanding.
	if len(fetch.wanted) > 0 {
		remaining := make([]string, 0, len(globDBSources))
		for _, source := range globDBSources {
			if _, done := byFile[source.file]; !done {
				remaining = append(remaining, source.file)
			}
		}
		if len(remaining) > 0 {
			fmt.Fprintf(os.Stderr, "  %s %d record(s) not in their finding's own file; sweeping %d more file(s)\n",
				terminal.InfoSymbol(), len(fetch.wanted), len(remaining))
			for _, file := range remaining {
				fetch.from(ctx, file, nil)
			}
		}
	}

	fmt.Fprintf(os.Stderr, "%s Resolved %d of %d record(s) in %s\n",
		terminal.InfoSymbol(), len(fetch.byUUID), len(uuids), time.Since(started).Round(time.Millisecond))
	return fetch.byUUID
}

// globRecordFetch is one hydration pass: the uuids still outstanding and the
// records found so far. The two are a pair — every resolved uuid moves from one
// to the other — so they travel as a receiver rather than as two maps that every
// call site has to remember to pass together.
type globRecordFetch struct {
	wanted map[string]struct{}
	byUUID map[string]*database.HTTPRecord
}

// done reports whether everything asked for has been found, so the caller can
// stop opening files.
func (f *globRecordFetch) done() bool { return len(f.wanted) == 0 }

// from opens one source file and takes whichever of its records are still
// outstanding. candidates narrows the lookup to the uuids a file is known to
// carry; nil asks it for everything still wanted (the fallback sweep).
func (f *globRecordFetch) from(ctx context.Context, file string, candidates []string) {
	if f.done() {
		return
	}
	outstanding := make([]string, 0, len(f.wanted))
	if candidates == nil {
		for uuid := range f.wanted {
			outstanding = append(outstanding, uuid)
		}
	} else {
		for _, uuid := range candidates {
			if _, ok := f.wanted[uuid]; ok {
				outstanding = append(outstanding, uuid)
			}
		}
	}
	if len(outstanding) == 0 {
		return
	}

	db, closeDB, err := openGlobSourceFile(ctx, file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %s %s — skipped: %v\n",
			terminal.WarningSymbol(), terminal.Cyan(filepath.Base(file)), err)
		return
	}
	defer closeDB()

	records, err := database.NewRepository(db).GetRecordsByUUIDs(ctx, outstanding)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %s %s — record lookup failed: %v\n",
			terminal.WarningSymbol(), terminal.Cyan(filepath.Base(file)), err)
		return
	}
	for _, record := range records {
		if _, ok := f.wanted[record.UUID]; !ok {
			continue
		}
		f.byUUID[record.UUID] = record
		delete(f.wanted, record.UUID)
	}
	if len(records) > 0 {
		fmt.Fprintf(os.Stderr, "  %s — %d record(s)\n", terminal.Cyan(filepath.Base(file)), len(records))
	}
}

// globFindingRecordPlan groups the wanted record uuids by the source file of the
// finding that references them, and returns the files in first-referenced order
// alongside that grouping. A finding whose id falls outside every recorded range
// (deduped during the merge, so its id belongs to the file that won) contributes
// its uuids to no file and is picked up by the fallback sweep.
func globFindingRecordPlan(
	findings []*database.Finding,
	wanted map[string]struct{},
) (order []string, byFile map[string][]string) {
	byFile = make(map[string][]string)
	for _, f := range findings {
		file := globSourceForFinding(f.ID)
		if file == "" {
			continue
		}
		for _, uuid := range f.HTTPRecordUUIDs {
			if _, ok := wanted[uuid]; !ok {
				continue
			}
			// First uuid for this file is what puts it in the visit order; the
			// grouping doubles as the seen-set.
			if len(byFile[file]) == 0 {
				order = append(order, file)
			}
			byFile[file] = append(byFile[file], uuid)
		}
	}
	return order, byFile
}
