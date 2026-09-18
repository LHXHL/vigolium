package database

import (
	"context"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// The corpus for attribution: one term, "needle", placed in exactly one location
// per record. Whatever --header and --body return, the union must not include a
// record whose needle lives in the other half.
func insertAttributionCorpus(t *testing.T, repo *Repository) map[string]string {
	t.Helper()
	return map[string]string{
		// needle as a request header VALUE only
		"header-only": insertRecordCorpus(t, repo, "/a", "needle", "nothing here"),
		// needle in the response BODY only
		"body-only": insertRecordCorpus(t, repo, "/b", "plain", "the needle is here"),
		// needle in both halves
		"both": insertRecordCorpus(t, repo, "/c", "needle", "needle again"),
		// needle nowhere
		"neither": insertRecordCorpus(t, repo, "/d", "plain", "nothing here"),
	}
}

func matchedUUIDs(t *testing.T, db *DB, f QueryFilters) map[string]bool {
	t.Helper()
	f.ProjectUUID = DefaultProjectUUID
	recs, err := NewQueryBuilder(db, f).Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := map[string]bool{}
	for _, r := range recs {
		out[r.UUID] = true
	}
	return out
}

// TestHeaderSearchIsAttributed is the regression this split exists for.
// --header used to scan raw_request/raw_response WHOLE, so a term appearing only
// in a response body came back as a header match.
func TestHeaderSearchIsAttributed(t *testing.T) {
	db := newTestDB(t)
	ids := insertAttributionCorpus(t, NewRepository(db))

	got := matchedUUIDs(t, db, QueryFilters{HeaderSearch: "needle"})

	if !got[ids["header-only"]] {
		t.Error("--header missed a record whose header carries the term")
	}
	if !got[ids["both"]] {
		t.Error("--header missed a record carrying the term in both halves")
	}
	if got[ids["body-only"]] {
		t.Error("--header matched a record whose term is only in the BODY — the bug this split fixes")
	}
	if got[ids["neither"]] {
		t.Error("--header matched a record that does not carry the term at all")
	}
}

// TestBodySearchIsAttributed is the mirror: --body must not match a header.
func TestBodySearchIsAttributed(t *testing.T) {
	db := newTestDB(t)
	ids := insertAttributionCorpus(t, NewRepository(db))

	got := matchedUUIDs(t, db, QueryFilters{BodySearch: "needle"})

	if !got[ids["body-only"]] {
		t.Error("--body missed a record whose body carries the term")
	}
	if !got[ids["both"]] {
		t.Error("--body missed a record carrying the term in both halves")
	}
	if got[ids["header-only"]] {
		t.Error("--body matched a record whose term is only in a HEADER — the bug this split fixes")
	}
	if got[ids["neither"]] {
		t.Error("--body matched a record that does not carry the term at all")
	}
}

// TestSearchStillSpansWholeExchange guards the other side of the contract:
// narrowing --header/--body must not narrow --search, which is documented as
// spanning headers + body and is the flag to reach for when location is
// irrelevant.
func TestSearchStillSpansWholeExchange(t *testing.T) {
	db := newTestDB(t)
	ids := insertAttributionCorpus(t, NewRepository(db))

	got := matchedUUIDs(t, db, QueryFilters{SearchTerms: []string{"needle"}})

	for _, key := range []string{"header-only", "body-only", "both"} {
		if !got[ids[key]] {
			t.Errorf("--search missed %s; it must span the whole exchange", key)
		}
	}
	if got[ids["neither"]] {
		t.Error("--search matched a record that does not carry the term")
	}
}

// TestRegionExcludeIsAttributed covers the negated forms. A NULL-safety or
// region mistake shows up here as the inverse of the positive bug: dropping rows
// that should have survived.
func TestRegionExcludeIsAttributed(t *testing.T) {
	db := newTestDB(t)
	ids := insertAttributionCorpus(t, NewRepository(db))

	t.Run("exclude-header keeps a body-only match", func(t *testing.T) {
		got := matchedUUIDs(t, db, QueryFilters{ExcludeHeaderSearch: "needle"})
		if !got[ids["body-only"]] {
			t.Error("--exclude-header dropped a record whose term is only in the body")
		}
		if !got[ids["neither"]] {
			t.Error("--exclude-header dropped a record that does not carry the term")
		}
		if got[ids["header-only"]] || got[ids["both"]] {
			t.Error("--exclude-header kept a record whose header carries the term")
		}
	})

	t.Run("exclude-body keeps a header-only match", func(t *testing.T) {
		got := matchedUUIDs(t, db, QueryFilters{ExcludeBodySearch: "needle"})
		if !got[ids["header-only"]] {
			t.Error("--exclude-body dropped a record whose term is only in a header")
		}
		if !got[ids["neither"]] {
			t.Error("--exclude-body dropped a record that does not carry the term")
		}
		if got[ids["body-only"]] || got[ids["both"]] {
			t.Error("--exclude-body kept a record whose body carries the term")
		}
	})
}

// TestRegionSearchEscapesWildcards ties the two fixes together: the region
// predicates must carry the ESCAPE clause, or an escaped term matches nothing.
func TestRegionSearchEscapesWildcards(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)

	literal := insertRecordCorpus(t, repo, "/pct", "plain", "discount is 100% off")
	other := insertRecordCorpus(t, repo, "/plain", "plain", "no percent sign here")

	got := matchedUUIDs(t, db, QueryFilters{BodySearch: "100%"})
	if !got[literal] {
		t.Error("--body '100%' missed the record whose body contains a literal 100%")
	}
	if got[other] {
		t.Error("--body '100%' matched a record with no percent sign: the % is still a wildcard")
	}

	// A bare wildcard must match only rows literally containing it.
	all := matchedUUIDs(t, db, QueryFilters{BodySearch: "%"})
	if all[other] {
		t.Error("--body '%' matched every row; the term is being read as a LIKE wildcard")
	}
}

// TestRegionSearchHandlesLFOnlyMessages covers a capture whose header block ends
// with a bare LF blank line rather than CRLF. The split must still land in the
// right place, or every such record reports its whole message as headers.
func TestRegionSearchHandlesLFOnlyMessages(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)

	id := insertRecordRaw(t, repo,
		"GET /lf HTTP/1.1\nHost: h.example.com\nX-Test: headerside\n\nbodyside payload")

	header := matchedUUIDs(t, db, QueryFilters{HeaderSearch: "headerside"})
	if !header[id] {
		t.Error("--header missed an LF-separated message's header")
	}
	if body := matchedUUIDs(t, db, QueryFilters{BodySearch: "headerside"}); body[id] {
		t.Error("--body matched an LF-separated message's HEADER")
	}

	if body := matchedUUIDs(t, db, QueryFilters{BodySearch: "bodyside"}); !body[id] {
		t.Error("--body missed an LF-separated message's body")
	}
	if header := matchedUUIDs(t, db, QueryFilters{HeaderSearch: "bodyside"}); header[id] {
		t.Error("--header matched an LF-separated message's BODY")
	}
}

// insertRecordRaw saves a record from a raw request string verbatim, so a test
// can control the exact byte layout — in particular the line endings that
// insertRecordCorpus's CRLF template does not vary.
func insertRecordRaw(t *testing.T, repo *Repository, raw string) string {
	t.Helper()
	rr, err := httpmsg.ParseRawRequest(raw)
	if err != nil {
		t.Fatalf("ParseRawRequest: %v", err)
	}
	u, err := repo.SaveRecord(context.Background(), rr, "test", DefaultProjectUUID)
	if err != nil {
		t.Fatalf("SaveRecord: %v", err)
	}
	return u
}

// TestURLsExactIsEquality covers --url: exact, never a prefix or a substring.
// The flag exists because callers reached for that name and the read surface had
// no equality selector for a URL — --path is fuzzy and a positional term is a
// substring search, so "this one endpoint" could not be asked for.
func TestURLsExactIsEquality(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)

	short := insertRecordCorpus(t, repo, "/admin", "plain", "short")
	long := insertRecordCorpus(t, repo, "/admin/config", "plain", "long")

	byExact := func(urls ...string) map[string]bool {
		return matchedUUIDs(t, db, QueryFilters{URLsExact: urls})
	}

	// insertRecordCorpus builds URLs as http(s)://h.example.com<path>; read the
	// stored value back rather than assuming the scheme.
	recs, err := NewQueryBuilder(db, QueryFilters{ProjectUUID: DefaultProjectUUID}).Execute(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	urlByUUID := map[string]string{}
	for _, r := range recs {
		urlByUUID[r.UUID] = r.URL
	}

	got := byExact(urlByUUID[short])
	if !got[short] {
		t.Error("exact URL did not select its own record")
	}
	// The short URL is a strict prefix of the long one. A LIKE would match both.
	if got[long] {
		t.Error("--url matched a record whose URL merely STARTS WITH the value")
	}

	if both := byExact(urlByUUID[short], urlByUUID[long]); !both[short] || !both[long] {
		t.Error("repeated --url values must OR together")
	}

	if none := byExact(urlByUUID[short] + "/nope"); len(none) != 0 {
		t.Errorf("a URL that is stored nowhere matched %d records", len(none))
	}

	// Blank values are dropped rather than matching a record with an empty URL.
	if blank := byExact("", "  "); len(blank) != 0 {
		t.Errorf("blank --url values selected %d records", len(blank))
	}
}
