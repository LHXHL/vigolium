package curl

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func parseCurlFixture(t *testing.T, name string) ([]*httpmsg.HttpRequestResponse, *observer.ObservedLogs) {
	t.Helper()
	core, logs := observer.New(zapcore.DebugLevel)
	t.Cleanup(zap.ReplaceGlobals(zap.New(core)))

	path := filepath.Join("testdata", name)
	var out []*httpmsg.HttpRequestResponse
	require.NoError(t, New().Parse(path, func(rr *httpmsg.HttpRequestResponse) bool {
		out = append(out, rr)
		return true
	}))
	return out, logs
}

func TestTokenize_ANSICQuoting(t *testing.T) {
	cases := map[string]string{
		`$'a\nb'`:        "a\nb",
		`$'it\'s'`:       "it's",
		`$'\\n'`:         `\n`,
		`$'\t\r\"\?'`:    "\t\r\"?",
		`$'\x41\x4a\x7'`: "AJ\x07",
		`$'☃\U0001F600'`: "☃😀",
		`$'\101\0'`:      "A\x00",
		`$'\e\cA'`:       "\x1b\x01",
		`$'\q'`:          `\q`,
		`pre$'mid'post`:  "premidpost",
		`$"plain $x"`:    "plain $x",
	}
	for in, want := range cases {
		got, err := tokenizeCurlCommand(in)
		require.NoError(t, err, in)
		assert.Equal(t, []string{want}, got, in)
	}
}

func TestTokenize_UnterminatedQuotes(t *testing.T) {
	for _, in := range []string{
		`curl -d 'abc http://x`,
		`curl -d "abc http://x`,
		`curl --data-raw $'abc http://x`,
		`curl --data-raw $'abc\'`,
		`curl http://x \`,
	} {
		_, err := tokenizeCurlCommand(in)
		assert.Error(t, err, in)
		_, err = ParseSingleCommand(in)
		assert.Error(t, err, in)
	}
}

func TestFixture_ChromeBash(t *testing.T) {
	rrs, logs := parseCurlFixture(t, "chrome_bash.txt")
	require.Len(t, rrs, 3)
	assert.Empty(t, logs.FilterLevelExact(zapcore.WarnLevel).All())

	notes := rrs[0].Request()
	assert.Equal(t, "POST", notes.Method())
	assert.Equal(t, "sid=abc123", notes.Header("Cookie"))
	assert.Equal(t,
		`{"title":"it's here","body":"line1\nline2","tab":"a`+"\t"+`b","snow":"☃","hex":"A"}`,
		string(notes.Body()))

	put := rrs[1].Request()
	assert.Equal(t, "PUT", put.Method())
	assert.Equal(t, "{\n  \"title\": \"multi\",\n  \"tags\": [\"a\", \"b\"]\n}", string(put.Body()))

	// `| jq .` ends the statement instead of becoming a second "URL".
	list := rrs[2].Request()
	assert.Equal(t, "GET", list.Method())
	assert.Equal(t, "/api/notes?limit=2", list.Path())

	count, err := New().Count(filepath.Join("testdata", "chrome_bash.txt"))
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

func TestFixture_ShellScriptMultiLineBody(t *testing.T) {
	rrs, logs := parseCurlFixture(t, "script.sh")
	require.Len(t, rrs, 2)
	assert.Empty(t, logs.FilterLevelExact(zapcore.WarnLevel).All())

	create := rrs[0].Request()
	assert.Equal(t, "POST", create.Method())
	assert.Equal(t, "{\n      \"name\": \"widget\"\n    }", string(create.Body()))
	assert.Equal(t, "/api/items", rrs[1].Request().Path())
}

func TestFixture_UnterminatedQuoteDoesNotSwallowRest(t *testing.T) {
	rrs, logs := parseCurlFixture(t, "unterminated.txt")
	require.Len(t, rrs, 1)
	assert.Equal(t, "/after-broken", rrs[0].Request().Path())

	warns := logs.FilterLevelExact(zapcore.WarnLevel).All()
	require.Len(t, warns, 1)
	assert.Contains(t, warns[0].ContextMap()["error"], "unterminated single quote")
}

func TestSplitStatements(t *testing.T) {
	in := "# it's a comment\n" +
		"curl a ; curl b\n" +
		"curl 'x\ny' # trailing comment\n" +
		"curl http://h/p;jsessionid=1\n" +
		"curl http://h/#frag\n" +
		"curl -d \"a\\\"b\nc\" u || true\n"
	assert.Equal(t, []string{
		"curl a",
		"curl b",
		"curl 'x\ny'",
		"curl http://h/p;jsessionid=1",
		"curl http://h/#frag",
		"curl -d \"a\\\"b\nc\" u",
		"true",
	}, splitStatements(in))
}
