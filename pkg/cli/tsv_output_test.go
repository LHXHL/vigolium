package cli

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTSVValueEscapesToOneLine(t *testing.T) {
	assert.Equal(t, `a\tb\nc\\d`, tsvValue("a\tb\nc\\d"))
	assert.Equal(t, "200", tsvValue(float64(200)))
	assert.Equal(t, "GET,POST", tsvValue([]any{"GET", "POST"}))
	assert.Equal(t, "", tsvValue(nil))
	assert.Equal(t, `{"a":1}`, tsvValue(map[string]any{"a": 1}))
}

func TestTrafficTSV(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	e := newB5Env(t)
	seedRefRecords(t, e)

	code, stdout, stderr := e.run(t, nil, "traffic", "--format", "tsv", "--sort", "uuid", "--asc")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	require.Len(t, lines, 4, "a header and one line per record in the project:\n%s", stdout)
	assert.Equal(t, "uuid_short\tstatus_code\tmethod\tresponse_content_length\turl", lines[0])
	assert.True(t, strings.HasPrefix(lines[1], "aaaa1111\t200\tGET\t"), lines[1])
	for _, l := range lines[1:] {
		assert.Len(t, strings.Split(l, "\t"), 5, "every row has one cell per column: %q", l)
	}

	// Byte-stable for a fixed store.
	_, again, _ := e.run(t, nil, "traffic", "--format", "tsv", "--sort", "uuid", "--asc")
	assert.Equal(t, stdout, again)

	// Columns are --fields names, aliases included, header as asked.
	code, stdout, stderr = e.run(t, nil, "traffic", "--format", "tsv", "--no-header", "--uuid", "bbbb2222",
		"--fields", "status,length,uuid_short,response_headers")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	cells := strings.Split(strings.TrimRight(stdout, "\n"), "\t")
	require.Len(t, cells, 4, stdout)
	assert.Equal(t, "200", cells[0])
	assert.Equal(t, "bbbb2222", cells[2])
	assert.Contains(t, cells[3], `X-Probe: /three`)
	assert.Contains(t, cells[3], `\r\n`, "the header block is escaped onto one line")

	code, _, _ = e.run(t, nil, "traffic", "--format", "tsv", "-j")
	assert.Equal(t, 2, code, "-j and --format tsv conflict")
	code, _, _ = e.run(t, nil, "traffic", "--format", "html")
	assert.Equal(t, 2, code, "traffic renders console or tsv")
}

func TestSchemaStorage(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	e := newB5Env(t)
	seedRefRecords(t, e)

	code, stdout, stderr := e.run(t, nil, "schema", "storage", "http_records", "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	doc := oneDoc(t, stdout, stderr)
	validateRegisteredMap(t, doc)
	items := doc["items"].([]any)
	require.Len(t, items, 1)
	table := items[0].(map[string]any)
	assert.Equal(t, "http_records", table["table"])
	assert.EqualValues(t, 4, table["rows"])
	assert.NotEmpty(t, table["purpose"])
	var hostCol map[string]any
	for _, c := range table["columns"].([]any) {
		if col := c.(map[string]any); col["name"] == "hostname" {
			hostCol = col
		}
	}
	require.NotNil(t, hostCol)
	assert.Equal(t, "host", hostCol["json_field"])

	code, _, _ = e.run(t, nil, "schema", "storage", "no_such_table")
	assert.Equal(t, 2, code)
}
