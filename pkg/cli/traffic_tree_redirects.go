package cli

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// redirectHeaderPrefixBytes bounds how much of a redirect's raw response is read
// back when the list query projected it away. A Location header lives in the
// status line + headers, so the body is never needed — and a redirect whose
// headers do not fit in this much is not one worth rendering a destination for.
const redirectHeaderPrefixBytes = 8192

// redirectLookupChunk bounds one uuid IN (...) lookup. SQLite's default host
// parameter limit is 999 and bun.List expands to one placeholder per element, so
// an unchunked list of a whole 3xx corpus is not a slow query, it is an error.
const redirectLookupChunk = 400

// redirectLocation returns the Location a 3xx response points at, or "" when the
// record is not a redirect or its raw response was not fetched.
//
// It reads the stored bytes rather than a column because there is no Location
// column: the destination is only ever recoverable from the response itself.
func redirectLocation(rec *database.HTTPRecord) string {
	if rec == nil || !isRedirectStatus(rec.StatusCode) || len(rec.RawResponse) == 0 {
		return ""
	}
	loc, err := httpmsg.GetHeaderValue(rec.RawResponse, "Location")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(loc)
}

// isRedirectStatus reports whether a status code is one that carries a Location.
// 304 is excluded: it is a cache validator, not a redirect, and has no
// destination to show.
func isRedirectStatus(code int) bool {
	return code >= 300 && code < 400 && code != http.StatusNotModified
}

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
		if rec != nil && rec.HasResponse && isRedirectStatus(rec.StatusCode) && len(rec.RawResponse) == 0 {
			pending[rec.UUID] = rec
		}
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

	for start := 0; start < len(uuids); start += redirectLookupChunk {
		end := min(start+redirectLookupChunk, len(uuids))
		var rows []struct {
			UUID        string `bun:"uuid"`
			RawResponse []byte `bun:"raw_response"`
		}
		err := db.NewSelect().
			Model((*database.HTTPRecord)(nil)).
			ColumnExpr("uuid").
			ColumnExpr("substr(raw_response, 1, ?) AS raw_response", redirectHeaderPrefixBytes).
			Where("uuid IN (?)", bun.List(uuids[start:end])).
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
