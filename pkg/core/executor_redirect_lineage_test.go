package core

import (
	"context"
	"testing"

	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/database"

	vighttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/work"
)

// hopRR builds a stand-in request/response pair for one chain hop.
func hopRR(t *testing.T, url, rawResp string) *httpmsg.HttpRequestResponse {
	t.Helper()
	rr, err := httpmsg.GetRawRequestFromURL(url)
	if err != nil {
		t.Fatalf("build hop %q: %v", url, err)
	}
	return rr.WithResponse(httpmsg.NewHttpResponse([]byte(rawResp)))
}

// TestSaveToDatabase_StampsChainLineage pins the three columns a consumer needs
// to make sense of a redirect chain from a single row: which submitted line it
// came from, which chain it belongs to, and whether the row after it is really
// where it pointed.
//
// Before these existed, "which of my 5,000 targets produced this" was only
// answerable by walking parent_uuid to the root — a whole-stream operation that
// a truncated chain can break outright, and one that a streaming consumer
// cannot do at all.
func TestSaveToDatabase_StampsChainLineage(t *testing.T) {
	e, db := newRepoExecutor(t)
	ctx := context.Background()

	const submitted = "app.example.test"
	redirect := "HTTP/1.1 302 Found\r\nLocation: /two\r\n\r\n"

	hops := []*httpmsg.HttpRequestResponse{
		hopRR(t, "http://app.example.test/one", redirect),
		hopRR(t, "http://app.example.test/two", redirect),
	}
	final := hopRR(t, "http://app.example.test/three",
		"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nok")

	item := work.NewWithModules(final, nil)
	item.Target = submitted

	e.saveToDatabase(ctx, item, final, hops)

	rows := selectRecordsByPath(t, db, ctx)
	if len(rows) != 3 {
		t.Fatalf("stored %d rows, want 3", len(rows))
	}

	root := rows["/one"]
	for path, rec := range rows {
		if rec.Target != submitted {
			t.Errorf("%s: target = %q, want %q — the row cannot name the line it came from", path, rec.Target, submitted)
		}
		if rec.RootUUID != root.UUID {
			t.Errorf("%s: root_uuid = %q, want the chain root %q", path, rec.RootUUID, root.UUID)
		}
	}
	if rows["/two"].ParentUUID != root.UUID {
		t.Errorf("/two parent = %q, want %q", rows["/two"].ParentUUID, root.UUID)
	}
	if rows["/three"].ParentUUID != rows["/two"].UUID {
		t.Errorf("/three parent = %q, want %q", rows["/three"].ParentUUID, rows["/two"].UUID)
	}
	for path, rec := range rows {
		if rec.ChainTruncated {
			t.Errorf("%s: chain_truncated set on a chain that reached its destination", path)
		}
	}
}

// TestSaveToDatabase_MarksTerminalRedirectTruncated is the other half: a chain
// whose final response is itself a 3xx did not arrive, it stopped — the follow
// cap, the mode's host rule, or the authentication gate. Without the flag that
// row is indistinguishable from a chain that legitimately ended at a redirect
// whose destination never answered, and the obvious consumer reading takes the
// 3xx as the final answer.
func TestSaveToDatabase_MarksTerminalRedirectTruncated(t *testing.T) {
	e, db := newRepoExecutor(t)
	ctx := context.Background()

	final := hopRR(t, "http://app.example.test/gate",
		"HTTP/1.1 302 Found\r\nLocation: https://login.example.test/oauth2/authorize\r\n\r\n")

	item := work.NewWithModules(final, nil)
	item.Target = "app.example.test"
	e.saveToDatabase(ctx, item, final, nil)

	rows := selectRecordsByPath(t, db, ctx)
	rec, ok := rows["/gate"]
	if !ok {
		t.Fatalf("no row stored; got %v", rows)
	}
	if !rec.ChainTruncated {
		t.Error("a terminal 3xx must be marked truncated: the chain stopped there rather than arriving")
	}
}

// TestCanonicalHopsDoNotMintRows is the end-to-end form of the collapse: a
// target whose only redirect is a scheme upgrade yields ONE record, at the
// canonical URL, naming the submitted line. It is what `curl -L host` shows.
func TestCanonicalHopsDoNotMintRows(t *testing.T) {
	e, db := newRepoExecutor(t)
	ctx := context.Background()

	hops := []*httpmsg.HttpRequestResponse{
		hopRR(t, "http://app.example.test/", "HTTP/1.1 301 Moved Permanently\r\nLocation: https://app.example.test/\r\n\r\n"),
	}
	final := hopRR(t, "https://app.example.test/", "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nok")

	item := work.NewWithModules(final, nil)
	item.Target = "app.example.test"
	// Shaped exactly as saveToDatabase shapes it, so the test exercises the
	// same reduction rather than a parallel copy of the rule.
	if rows := vighttp.ShapeRedirectChain(hops, final.Target()); len(rows) != 0 {
		t.Fatalf("a scheme-upgrade hop still mints %d row(s)", len(rows))
	}
	e.saveToDatabase(ctx, item, final, hops)

	rows := selectRecordsByPath(t, db, ctx)
	if len(rows) != 1 {
		t.Fatalf("stored %d rows, want 1 (the canonical destination only): %v", len(rows), rows)
	}
	if rows["/"].Target != "app.example.test" {
		t.Errorf("target = %q, want the submitted line", rows["/"].Target)
	}
}

// selectRecordsByPath reads every stored record keyed by its path.
func selectRecordsByPath(t *testing.T, db interface {
	NewSelect() *bun.SelectQuery
}, ctx context.Context) map[string]*database.HTTPRecord {
	t.Helper()
	var recs []*database.HTTPRecord
	if err := db.NewSelect().Model(&recs).Scan(ctx); err != nil {
		t.Fatalf("select records: %v", err)
	}
	out := make(map[string]*database.HTTPRecord, len(recs))
	for _, r := range recs {
		out[r.Path] = r
	}
	return out
}
