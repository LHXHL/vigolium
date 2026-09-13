package cli

import (
	"context"
	"fmt"
	"os"
	"slices"

	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// redirectHeaderPrefixBytes bounds how much of a redirect's raw response is read
// back when the list query projected it away. A Location header lives in the
// status line + headers, so the body is never needed — and a redirect whose
// headers do not fit in this much is not one worth rendering a destination for.
const redirectHeaderPrefixBytes = 8192

// redirectLocation returns where a 3xx record points, for the renderers.
//
// A thin delegation on purpose: the column-first / raw-fallback rule and the
// "what counts as a redirect" rule both live beside the write path that fills
// the column, so the read path cannot drift from it.
func redirectLocation(rec *database.HTTPRecord) string { return rec.RedirectLocation() }

// isRedirectStatus reports whether a status code is one that carries a Location.
// Delegates for the same reason as redirectLocation.
func isRedirectStatus(code int) bool { return database.IsRedirectStatus(code) }

// hydrateRedirectHeaders fills in the raw response headers of the redirect
// records in the page, for the render paths that asked the query to leave the
// raw bodies out (see QueryBuilder.OmitBodies).
//
// The alternative — telling the query to hydrate raw_response because the tree
// *might* show a Location — would pull the whole matched corpus into memory to
// recover one header per redirect, which is exactly the cost OmitBodies exists
// to avoid; on a `--glob-db` read it would also force the merge to copy every
// file's bodies. So the destinations are fetched afterwards, by uuid, for the
// 3xx subset alone, and capped at the header prefix.
//
// Records are mutated in place, and only where RawResponse was empty: a caller
// that already has the full response keeps it rather than having it replaced by
// a truncated prefix. This is safe because it runs at the end of the read path,
// immediately before rendering, with nothing downstream that reads a body.
func hydrateRedirectHeaders(ctx context.Context, db *database.DB, records []*database.HTTPRecord) {
	pending := make(map[string]*database.HTTPRecord)
	for _, rec := range records {
		if rec == nil || !rec.HasResponse || !isRedirectStatus(rec.StatusCode) {
			continue
		}
		// The stored destination makes the whole fetch unnecessary. Only records
		// written before response_location existed still need their bytes read
		// back, so on a current corpus this loop selects nothing and the work
		// below — a query per chunk, or a source-file reopen per file under
		// --glob-db — does not happen at all.
		if rec.ResponseLocation != "" || len(rec.RawResponse) > 0 {
			continue
		}
		pending[rec.UUID] = rec
	}
	if len(pending) == 0 {
		return
	}

	// Under --glob-db the merge may have skipped the body columns outright, so
	// the scratch database cannot answer this; each record's own source file can.
	// The merge's own record of what it skipped is the single owner of that
	// question — re-deriving it from the flags here is how the two disagree and
	// the destination silently renders empty.
	if globMergeOmittedRecords() {
		resolveGlobRecordSources(ctx, db, records)
		hydrateRedirectHeadersFromGlob(ctx, pending)
		return
	}
	readRedirectHeaders(ctx, db, pending)
}

// hydrateRedirectHeadersFromGlob resolves redirect headers out of the --glob-db
// source files, grouping the outstanding uuids by the file each record was
// merged from (globSourceForRecord) so a file is opened at most once.
//
// A record the attribution cannot place is left alone rather than swept for
// across every file: the tree degrades to the line it printed before, whereas a
// sweep over hundreds of files would make a display detail the most expensive
// part of the command.
func hydrateRedirectHeadersFromGlob(ctx context.Context, pending map[string]*database.HTTPRecord) {
	byFile := make(map[string]map[string]*database.HTTPRecord)
	for uuid, rec := range pending {
		file := globSourceForRecord(uuid)
		if file == "" {
			continue
		}
		if byFile[file] == nil {
			byFile[file] = make(map[string]*database.HTTPRecord)
		}
		byFile[file][uuid] = rec
	}
	for _, source := range globDBSources {
		batch := byFile[source.file]
		if len(batch) == 0 {
			continue
		}
		db, closeDB, err := openGlobSourceFile(ctx, source.file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s redirect targets unavailable for %s: %v\n",
				terminal.WarningSymbol(), terminal.Cyan(terminal.ShortenHome(source.file)), err)
			continue
		}
		readRedirectHeaders(ctx, db, batch)
		closeDB()
	}
}

// readRedirectHeaders selects the capped header prefix for the given records
// from one database and writes it onto them.
//
// A failure is reported once and swallowed: the destination is an enrichment of
// a line that already renders, so failing the whole listing over it would turn a
// missing detail into no output at all.
func readRedirectHeaders(ctx context.Context, db *database.DB, pending map[string]*database.HTTPRecord) {
	if db == nil || len(pending) == 0 {
		return
	}
	uuids := make([]string, 0, len(pending))
	for uuid := range pending {
		uuids = append(uuids, uuid)
	}

	// database.SQLChunkSize, not a local constant: this used to be 400, chosen
	// against SQLite's pre-3.32 limit of 999 bound parameters. Neither number
	// applies — bun renders a list as SQL literals, so there is no parameter
	// ceiling here at all and what needs bounding is the generated SQL's length,
	// which is the one policy SQLChunkSize owns.
	for chunk := range slices.Chunk(uuids, database.SQLChunkSize) {
		var rows []struct {
			UUID        string `bun:"uuid"`
			RawResponse []byte `bun:"raw_response"`
		}
		err := db.NewSelect().
			Model((*database.HTTPRecord)(nil)).
			ColumnExpr("uuid").
			ColumnExpr("substr(raw_response, 1, ?) AS raw_response", redirectHeaderPrefixBytes).
			Where("uuid IN (?)", bun.List(chunk)).
			Scan(ctx, &rows)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s redirect targets unavailable: %v\n", terminal.WarningSymbol(), err)
			return
		}
		for _, row := range rows {
			if rec := pending[row.UUID]; rec != nil && len(rec.RawResponse) == 0 {
				rec.RawResponse = row.RawResponse
			}
		}
	}
}
