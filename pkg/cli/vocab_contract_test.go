package cli

import (
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The field-vocabulary contract, driven through the real CLI: for every -j
// list command that takes --fields, (a) its document validates against its
// registered schema, (b) every key its rows emit is accepted back by --fields,
// and (c) the shared aliases (status, length, title, …) resolve on it and come
// back under the name asked for. A command that renames a key, or grows one
// without its --fields vocabulary, fails here instead of in a caller's parser.

type vocabCase struct {
	name string
	args []string
	// aliases are spellings that must resolve on this command, mapped to the
	// value-bearing key they stand for (checked for presence, not value).
	aliases []string
}

func emittedItemKeys(t *testing.T, doc map[string]any) []string {
	t.Helper()
	items, ok := doc["items"].([]any)
	require.True(t, ok, "items must be an array")
	require.NotEmpty(t, items, "the seeded store must produce at least one row")
	seen := map[string]bool{}
	for _, it := range items {
		row, ok := it.(map[string]any)
		require.True(t, ok, "rows are objects")
		for k := range row {
			seen[k] = true
		}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func TestFieldVocabularyContract(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	srv, _ := countingServer(t)
	e := newB5Env(t)
	code, stdout, stderr := e.run(t, nil, "db", "seed")
	require.Equal(t, 0, code, "db seed: stdout:\n%s\nstderr:\n%s", stdout, stderr)

	cases := []vocabCase{
		{name: "traffic", args: []string{"traffic", "-j", "--compact"},
			aliases: []string{"status", "length", "id", "uuid_short", "words"}},
		{name: "finding", args: []string{"finding", "-j", "--compact"}},
		{name: "endpoints", args: []string{"endpoints", "-j"},
			aliases: []string{"status_code"}},
		{name: "params", args: []string{"params", "-j"}},
		{name: "fuzz", args: []string{"fuzz", srv.URL + "/v?q=FUZZ", "-p", "a", "-p", "b", "--match-status-code", "200", "--no-calibrate", "-j"},
			aliases: []string{"status_code", "response_content_length", "response_words"}},
		{name: "replay", args: []string{"replay", "-i", "curl '" + srv.URL + "/r'", "-j"}},
		{name: "log ls", args: []string{"log", "ls", "-j"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, stdout, stderr := e.run(t, nil, c.args...)
			require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
			doc := oneDoc(t, stdout, stderr)
			validateRegisteredMap(t, doc)

			keys := emittedItemKeys(t, doc)
			code, stdout, stderr = e.run(t, nil, append(slices.Clone(c.args), "--fields", strings.Join(keys, ","))...)
			require.Equal(t, 0, code, "every emitted key must be accepted by --fields\nkeys: %v\nstdout:\n%s\nstderr:\n%s", keys, stdout, stderr)

			if len(c.aliases) == 0 {
				return
			}
			code, stdout, stderr = e.run(t, nil, append(slices.Clone(c.args), "--fields", strings.Join(c.aliases, ","))...)
			require.Equal(t, 0, code, "aliases %v must resolve\nstdout:\n%s\nstderr:\n%s", c.aliases, stdout, stderr)
			projected := oneDoc(t, stdout, stderr)
			for _, it := range projected["items"].([]any) {
				row := it.(map[string]any)
				for k := range row {
					assert.Contains(t, c.aliases, k, "a projected row carries only the names asked for")
				}
			}
			first := projected["items"].([]any)[0].(map[string]any)
			for _, a := range c.aliases {
				_, ok := first[a]
				assert.True(t, ok, "alias %q comes back under its own name: %v", a, first)
			}
		})
	}
}

func TestFieldsUnknownNameSuggests(t *testing.T) {
	err := validateFieldSelection([]string{"staus_code"}, trafficViewFields)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "did you mean: staus_code → status_code")
	assert.Contains(t, err.Error(), "also accepted")
}

func TestFieldAliasesResolveAgainstTheViewsOwnKeys(t *testing.T) {
	has := func(keys ...string) func(string) bool {
		return func(k string) bool { return slices.Contains(keys, k) }
	}
	// A real key wins over an alias: endpoints' status is its histogram.
	got, ok := resolveFieldName("status", has("status", "top_status"))
	require.True(t, ok)
	assert.Equal(t, "status", got)
	got, ok = resolveFieldName("status_code", has("status", "top_status"))
	require.True(t, ok)
	assert.Equal(t, "top_status", got, "the scalar, not the histogram")
	got, ok = resolveFieldName("length", has("response_content_length"))
	require.True(t, ok)
	assert.Equal(t, "response_content_length", got)
	_, ok = resolveFieldName("nope", has("uuid"))
	assert.False(t, ok)

	row := map[string]any{"status_code": 200, "response_content_length": 12, "uuid": "u"}
	assert.Equal(t, map[string]any{"status": 200, "length": 12, "id": "u"},
		projectFields(row, []string{"status", "length", "id"}))
}
