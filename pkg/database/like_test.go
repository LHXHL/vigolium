package database

import "testing"

func TestEscapeLikeLiteral(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain text untouched", "password", "password"},
		{"percent escaped", "100%", `100\%`},
		{"underscore escaped", "api_key", `api\_key`},
		{"backslash escaped first", `a\b`, `a\\b`},
		// A backslash already in front of a metacharacter must survive as DATA:
		// escaping the metacharacter first would produce `\\%`, which reads as a
		// literal backslash followed by the wildcard — the leak this guards.
		{"backslash before percent", `a\%b`, `a\\\%b`},
		{"url-encoded payload", "%2e%2e%2f", `\%2e\%2e\%2f`},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := EscapeLikeLiteral(tc.in); got != tc.want {
				t.Errorf("EscapeLikeLiteral(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestLikeContains(t *testing.T) {
	if got, want := LikeContains("api_key"), `%api\_key%`; got != want {
		t.Errorf("LikeContains = %q, want %q", got, want)
	}
	// The wrapping % are the pattern's own; only the term is escaped.
	if got, want := LikeContains("%"), `%\%%`; got != want {
		t.Errorf("LikeContains = %q, want %q", got, want)
	}
}

func TestLikeGlob(t *testing.T) {
	cases := []struct{ in, want string }{
		{"*.example.com", `%.example.com`},
		{"api.*.internal", `api.%.internal`},
		// A literal metacharacter stays literal even in glob mode; only `*` is a
		// wildcard in the documented --host/--path vocabulary.
		{"a_b*", `a\_b%`},
		{"100%*", `100\%%`},
		{"exact.host", "exact.host"},
	}
	for _, tc := range cases {
		if got := LikeGlob(tc.in); got != tc.want {
			t.Errorf("LikeGlob(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestWithLikeEscape(t *testing.T) {
	got := WithLikeEscape("(a LIKE ? OR b LIKE ?)")
	want := `(a LIKE ? ESCAPE '\' OR b LIKE ? ESCAPE '\')`
	if got != want {
		t.Errorf("WithLikeEscape = %q, want %q", got, want)
	}
}

// TestSearchPredicatesCarryEscape is the guard that matters: every shared
// predicate must have an ESCAPE for each of its placeholders, or the term
// escaping above turns backslashes into literal data the corpus does not
// contain and the filter silently matches nothing.
func TestSearchPredicatesCarryEscape(t *testing.T) {
	preds := map[string]string{
		"recordSearchPredicate":           recordSearchPredicate,
		"findingSearchPredicate":          findingSearchPredicate,
		"fuzzyRecordPredicate":            fuzzyRecordPredicate,
		"fuzzyRecordFTSPredicate":         fuzzyRecordFTSPredicate,
		"fuzzyRecordPostgresFTSPredicate": fuzzyRecordPostgresFTSPredicate,
		"fuzzyFindingPredicate":           fuzzyFindingPredicate,
		"remarkPredicateSQLite":           remarkPredicateSQLite,
		"remarkPredicatePostgres":         remarkPredicatePostgres,
		// The region predicates are built per driver, so both spellings are
		// checked: an ESCAPE added to only one would make --header behave
		// differently on Postgres than on SQLite.
		"headerSearchPredicate/sqlite":         headerSearchPredicate("sqlite"),
		"headerSearchPredicate/postgres":       headerSearchPredicate("postgres"),
		"bodySearchPredicate/sqlite":           bodySearchPredicate("sqlite"),
		"bodySearchPredicate/postgres":         bodySearchPredicate("postgres"),
		"findingRegionPredicate/header-sqlite": findingRegionPredicate(headerSearchPredicate("sqlite")),
		"findingRegionPredicate/body-postgres": findingRegionPredicate(bodySearchPredicate("postgres")),
	}
	for name, pred := range preds {
		t.Run(name, func(t *testing.T) {
			bare := countOccurrences(pred, "LIKE ?")
			escaped := countOccurrences(pred, `LIKE ? ESCAPE '\'`)
			if bare == 0 {
				t.Fatalf("%s has no LIKE placeholder", name)
			}
			if bare != escaped {
				t.Errorf("%s: %d LIKE placeholders but %d carry ESCAPE", name, bare, escaped)
			}
		})
	}
}

func countOccurrences(s, sub string) int {
	n := 0
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			n++
		}
	}
	return n
}
