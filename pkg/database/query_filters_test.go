package database

import "testing"

// TestQueryFilters_UsesRawCorpus pins every filter that reaches the
// raw_request/raw_response columns. Callers skip copying or selecting those
// blobs when this returns false, and the cost of a wrong answer is silent: a
// missed field makes --search match nothing and --exclude-* match everything.
func TestQueryFilters_UsesRawCorpus(t *testing.T) {
	t.Run("no filters", func(t *testing.T) {
		if (QueryFilters{}).UsesRawCorpus() {
			t.Fatal("empty filters reported a raw-corpus read")
		}
	})

	t.Run("metadata-only filters", func(t *testing.T) {
		// The case that matters for --glob-db: these all resolve against indexed
		// metadata columns, so the bodies are genuinely unnecessary.
		f := QueryFilters{
			HostPattern: "acme.com",
			Methods:     []string{"GET"},
			StatusCodes: []int{200},
			PathPattern: "/api",
			ContentType: "application/json",
		}
		if f.UsesRawCorpus() {
			t.Fatal("metadata-only filters reported a raw-corpus read")
		}
	})

	for _, tc := range []struct {
		name   string
		filter QueryFilters
	}{
		{"fuzzy term", QueryFilters{FuzzyTerm: "admin"}},
		{"search terms", QueryFilters{SearchTerms: []string{"admin"}}},
		{"single search term", QueryFilters{SearchTerm: "admin"}},
		{"header search", QueryFilters{HeaderSearch: "Authorization"}},
		{"body search", QueryFilters{BodySearch: "password"}},
		{"exclude terms", QueryFilters{ExcludeTerms: []string{"noise"}}},
		{"exclude header", QueryFilters{ExcludeHeaderSearch: "Set-Cookie"}},
		{"exclude body", QueryFilters{ExcludeBodySearch: "noise"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.filter.UsesRawCorpus() {
				t.Fatalf("%s must report a raw-corpus read: it LIKEs over raw_request/raw_response", tc.name)
			}
		})
	}

	t.Run("blank terms do not count", func(t *testing.T) {
		// EffectiveSearchTerms drops blanks, so a blank must not pin the bodies.
		f := QueryFilters{SearchTerms: []string{""}, ExcludeTerms: []string{""}}
		if f.UsesRawCorpus() {
			t.Fatal("blank-only terms reported a raw-corpus read")
		}
	})
}

// UsesLinkedRecords is the gate on dropping http_records from a --glob-db merge
// for a FINDINGS read. Every filter listed here resolves through an EXISTS over
// the finding_records junction in applyFindingFilters, so omitting the table
// makes it match nothing (or, negated, everything) with no error raised.
func TestUsesLinkedRecordsCoversEveryRecordBackedFindingFilter(t *testing.T) {
	if (QueryFilters{}).UsesLinkedRecords() {
		t.Fatal("an unfiltered read must not drag http_records into the merge")
	}

	cases := map[string]QueryFilters{
		"host":           {HostPattern: "api.example"},
		"path":           {PathPattern: "/admin"},
		"method":         {Methods: []string{"POST"}},
		"status":         {StatusCodes: []int{500}},
		"source":         {Source: "burp"},
		"search":         {SearchTerms: []string{"jwt"}},
		"exclude":        {ExcludeTerms: []string{"jwt"}},
		"fuzzy":          {FuzzyTerm: "jwt"},
		"header":         {HeaderSearch: "authorization"},
		"body":           {BodySearch: "password"},
		"exclude-header": {ExcludeHeaderSearch: "authorization"},
		"exclude-body":   {ExcludeBodySearch: "password"},
	}
	for name, filters := range cases {
		if !filters.UsesLinkedRecords() {
			t.Errorf("--%s resolves through http_records but UsesLinkedRecords() is false", name)
		}
	}
}

// The raw-corpus subset is strictly narrower: a metadata filter needs the rows
// but not the blobs, which is what lets the merge drop ~96% of the bytes.
func TestUsesLinkedRecordsIsWiderThanUsesRawCorpus(t *testing.T) {
	metadataOnly := QueryFilters{HostPattern: "api.example", StatusCodes: []int{200}}
	if !metadataOnly.UsesLinkedRecords() {
		t.Fatal("host/status need the record rows")
	}
	if metadataOnly.UsesRawCorpus() {
		t.Fatal("host/status must not force the raw bodies into the merge")
	}
}
