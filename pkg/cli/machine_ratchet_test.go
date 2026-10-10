package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/jsext"
)

// The last commands off the -j contract (plan B8), driven through the real
// Execute() in a child process (machine_mutations_test.go's b5Env): one
// document on stdout, the declared kind, and the schema the command registers.

// requireRead asserts a read document and returns items.
func requireRead(t *testing.T, doc map[string]any, command string) []any {
	t.Helper()
	require.EqualValues(t, AgentSchemaVersion, doc["schema_version"])
	require.Equal(t, command, doc["command"])
	require.Equal(t, true, doc["ok"])
	require.Equal(t, string(kindRead), doc["kind"])
	items, ok := doc["items"].([]any)
	require.True(t, ok, "items must be an array: %v", doc["items"])
	validateRegisteredMap(t, doc)
	return items
}

// requireUsageError asserts the one usage_error document and exit 2.
func requireUsageDoc(t *testing.T, code int, stdout, stderr string) {
	t.Helper()
	require.Equal(t, 2, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	doc := oneDoc(t, stdout, stderr)
	require.Equal(t, false, doc["ok"])
	require.Equal(t, "usage_error", doc["error"].(map[string]any)["code"])
	validateRegisteredMap(t, doc)
}

func TestDBSeedJSON(t *testing.T) {
	e := newB5Env(t)
	code, stdout, stderr := e.run(t, nil, "db", "seed", "-j")
	require.Equal(t, 0, code, stderr)
	doc := oneDoc(t, stdout, stderr)
	items := requireMutation(t, doc, "db seed", true)
	require.NotEmpty(t, items)
	require.Equal(t, "users", items[0].(map[string]any)["table"])
	require.Greater(t, doc["rows_inserted"], float64(0))
	require.Contains(t, stderr, "Seeding database", "progress moves to stderr under -j")

	// A re-seed under --force skips the rows that are already there (scan_logs
	// has no natural key, so its lines are appended again).
	code, stdout, stderr = e.run(t, nil, "--force", "db", "seed", "-j")
	require.Equal(t, 0, code, stderr)
	doc = oneDoc(t, stdout, stderr)
	items = requireMutation(t, doc, "db seed", true)
	for _, it := range items {
		row := it.(map[string]any)
		if row["table"] != "scan_logs" {
			require.EqualValues(t, 0, row["inserted"], "re-seeded %s", row["table"])
		}
	}
}

func TestExtensionsExamplePresetTypesJSON(t *testing.T) {
	e := newB5Env(t)

	code, stdout, stderr := e.run(t, nil, "extensions", "example", "yaml", "-j")
	require.Equal(t, 0, code, stderr)
	items := requireRead(t, oneDoc(t, stdout, stderr), "extensions example")
	require.NotEmpty(t, items)
	first := items[0].(map[string]any)
	require.Equal(t, "yaml", first["lang"])
	require.NotEmpty(t, first["code"])

	code, stdout, stderr = e.run(t, nil, "extensions", "example", "--list", "-j")
	require.Equal(t, 0, code, stderr)
	doc := oneDoc(t, stdout, stderr)
	items = requireRead(t, doc, "extensions example")
	require.NotContains(t, items[0].(map[string]any), "code", "--list is the index only")
	require.Equal(t, true, doc["list_only"])

	code, stdout, stderr = e.run(t, nil, "extensions", "example", "no-such-example-xyz", "-j")
	require.Equal(t, 1, code, stderr)
	require.Equal(t, "not_found", oneDoc(t, stdout, stderr)["error"].(map[string]any)["code"])

	code, stdout, stderr = e.run(t, nil, "extensions", "preset", "-j")
	require.Equal(t, 0, code, stderr)
	doc = oneDoc(t, stdout, stderr)
	items = requireMutation(t, doc, "extensions preset", true)
	last := items[len(items)-1].(map[string]any)
	require.Equal(t, jsext.TypeDefinitionsFileName, last["name"])
	require.Equal(t, "updated", last["status"])

	// Everything is in place now: the second run changes nothing.
	code, stdout, stderr = e.run(t, nil, "extensions", "preset", "-j")
	require.Equal(t, 0, code, stderr)
	doc = oneDoc(t, stdout, stderr)
	items = requireMutation(t, doc, "extensions preset", false)
	require.Equal(t, "current", items[len(items)-1].(map[string]any)["status"])
	require.EqualValues(t, 0, doc["installed"])

	// Without -o the declarations travel inside the document, not beside it.
	code, stdout, stderr = e.run(t, nil, "extensions", "types", "-j")
	require.Equal(t, 0, code, stderr)
	items = requireRead(t, oneDoc(t, stdout, stderr), "extensions types")
	require.Len(t, items, 1)
	require.Equal(t, jsext.TypeDefinitions(), items[0].(map[string]any)["content"])

	dest := filepath.Join(e.home, "types-out")
	require.NoError(t, os.MkdirAll(dest, 0o755))
	code, stdout, stderr = e.run(t, nil, "extensions", "types", "-o", dest, "-j")
	require.Equal(t, 0, code, stderr)
	items = requireRead(t, oneDoc(t, stdout, stderr), "extensions types")
	require.NotContains(t, items[0].(map[string]any), "content")
	require.FileExists(t, filepath.Join(dest, jsext.TypeDefinitionsFileName))
}

func TestExtensionsEvalJSON(t *testing.T) {
	e := newB5Env(t)
	code, stdout, stderr := e.run(t, nil, "extensions", "eval", "[1, 'a']", "-j")
	require.Equal(t, 0, code, stderr)
	items := requireRead(t, oneDoc(t, stdout, stderr), "extensions eval")
	require.Equal(t, []any{float64(1), "a"}, items[0].(map[string]any)["value"])
}

// TestJSAndImportReadGlobalFormat: the local --format that shadowed the global
// flag is gone; both commands read the global one.
func TestJSAndImportReadGlobalFormat(t *testing.T) {
	require.Nil(t, jsCmd.LocalNonPersistentFlags().Lookup("format"))
	require.Nil(t, importCmd.LocalNonPersistentFlags().Lookup("format"))

	e := newB5Env(t)
	code, stdout, stderr := e.run(t, nil, "js", "--code", `"hi"`, "--format", "text")
	require.Equal(t, 0, code, stderr)
	require.Equal(t, "hi\n", stdout)

	code, stdout, stderr = e.run(t, nil, "js", "--code", `"hi"`)
	require.Equal(t, 0, code, stderr)
	require.Equal(t, "\"hi\"\n", stdout, "json stays the default")

	code, stdout, stderr = e.run(t, nil, "js", "--code", `1+1`, "--format", "html", "-j")
	requireUsageDoc(t, code, stdout, stderr)

	code, stdout, stderr = e.run(t, nil, "js", "--code", `({a: 1})`, "-j")
	require.Equal(t, 0, code, stderr)
	items := requireRead(t, oneDoc(t, stdout, stderr), "js")
	require.Equal(t, map[string]any{"a": float64(1)}, items[0].(map[string]any)["value"])

	src := writeImportJSONL(t, e.home)
	code, stdout, stderr = e.run(t, nil, "import", src, "--format", "nonsense", "-o", filepath.Join(e.home, "r.md"), "-j")
	requireUsageDoc(t, code, stdout, stderr)

	report := filepath.Join(e.home, "r.md")
	code, stdout, stderr = e.run(t, nil, "import", src, "--format", "markdown", "-o", report, "-j")
	require.Equal(t, 0, code, stderr)
	doc := oneDoc(t, stdout, stderr)
	requireMutation(t, doc, "import", true)
	require.Equal(t, report, doc["report_path"])
	require.FileExists(t, report)
}

func TestLogUUIDJSON(t *testing.T) {
	e := newB5Env(t)
	code, _, stderr := e.run(t, nil, "db", "seed", "-j")
	require.Equal(t, 0, code, stderr)

	// The seeded scans have no runtime.log, so the lines come from scan_logs.
	const seeded = "scan-0001-aaaa-bbbb-cccc-ddddeeee0001"
	code, stdout, stderr := e.run(t, nil, "log", seeded, "-j")
	require.Equal(t, 0, code, stderr)
	doc := oneDoc(t, stdout, stderr)
	items := requireRead(t, doc, "log")
	require.NotEmpty(t, items)
	require.Equal(t, "database", doc["source"])
	require.Equal(t, seeded, doc["uuid"])
	require.Equal(t, "native", doc["session_kind"])
	require.NotEmpty(t, items[0].(map[string]any)["text"])
	require.NotEmpty(t, items[0].(map[string]any)["level"])

	code, stdout, stderr = e.run(t, nil, "log", seeded, "--tail", "2", "-j")
	require.Equal(t, 0, code, stderr)
	doc = oneDoc(t, stdout, stderr)
	require.Len(t, requireRead(t, doc, "log"), 2)
	require.Equal(t, true, doc["truncated"])

	code, stdout, stderr = e.run(t, nil, "log", seeded, "--follow", "-j")
	requireUsageDoc(t, code, stdout, stderr)
}

func TestReadLogFileLinesTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.log")
	require.NoError(t, os.WriteFile(path, []byte("one\n\x1b[31mtwo\x1b[0m\nthree\n"), 0o600))

	lines, truncated, err := readLogFileLines(path, -1)
	require.NoError(t, err)
	require.False(t, truncated)
	require.Equal(t, []logLineView{{Text: "one"}, {Text: "two"}, {Text: "three"}}, lines)

	lines, truncated, err = readLogFileLines(path, 2)
	require.NoError(t, err)
	require.True(t, truncated)
	require.Equal(t, []logLineView{{Text: "two"}, {Text: "three"}}, lines)

	lines, _, err = readLogFileLines(path, 0)
	require.NoError(t, err)
	require.Empty(t, lines)
}

func TestExportJSONReceipts(t *testing.T) {
	e := newB5Env(t)
	code, _, stderr := e.run(t, nil, "db", "seed", "-j")
	require.Equal(t, 0, code, stderr)

	// The export stream and the document cannot share stdout.
	code, stdout, stderr := e.run(t, nil, "export", "-j")
	requireUsageDoc(t, code, stdout, stderr)
	code, stdout, stderr = e.run(t, nil, "db", "export", "-j")
	requireUsageDoc(t, code, stdout, stderr)

	out := filepath.Join(e.home, "all.jsonl")
	code, stdout, stderr = e.run(t, nil, "export", "-o", out, "-j")
	require.Equal(t, 0, code, stderr)
	doc := oneDoc(t, stdout, stderr)
	items := requireRead(t, doc, "export")
	require.Len(t, items, 1)
	require.Equal(t, "jsonl", items[0].(map[string]any)["format"])
	require.Equal(t, out, items[0].(map[string]any)["path"])
	counts := doc["counts"].(map[string]any)
	require.Greater(t, counts["total"], float64(0))
	require.FileExists(t, out)

	out = filepath.Join(e.home, "records.csv")
	code, stdout, stderr = e.run(t, nil, "db", "export", "--format", "csv", "-o", out, "-j")
	require.Equal(t, 0, code, stderr)
	doc = oneDoc(t, stdout, stderr)
	items = requireRead(t, doc, "db export")
	require.Equal(t, "csv", items[0].(map[string]any)["format"])
	require.Greater(t, doc["counts"].(map[string]any)["records"], float64(0))
	require.FileExists(t, out)
}
