package postman

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// parseData parses data and returns path -> Authorization header, in emission order.
func parseData(t *testing.T, data string) ([]string, map[string]string, *Format) {
	t.Helper()
	f := New()
	var order []string
	auth := map[string]string{}
	err := f.ParseFromData([]byte(data), func(rr *httpmsg.HttpRequestResponse) bool {
		u, err := rr.URL()
		require.NoError(t, err)
		order = append(order, u.Path)
		auth[u.Path] = rr.Request().Header("Authorization")
		return true
	})
	require.NoError(t, err)
	return order, auth, f
}

// Postman writes collection auth/variables and a folder's auth AFTER the
// items they apply to; the streaming parser must still apply them.
const trailingBlocks = `{
  "info": {"name": "trailing"},
  "item": [
    {"name": "plain", "item": [
      {"name": "a", "request": {"method": "GET", "url": "{{baseUrl}}/a"}}
    ]},
    {"name": "basic folder", "item": [
      {"name": "nested", "item": [
        {"name": "b", "request": {"method": "GET", "url": "{{baseUrl}}/b"}},
        {"name": "c", "request": {"method": "GET", "url": "{{baseUrl}}/c", "auth": {"type": "noauth"}}}
      ]},
      {"name": "d", "request": {"method": "GET", "url": "{{baseUrl}}/d"}}
    ], "auth": {"type": "basic", "basic": [{"key": "username", "value": "u"}, {"key": "password", "value": "p"}]}},
    {"name": "leaf auth", "request": {"method": "GET", "url": "{{baseUrl}}/e"}, "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "leaf"}]}},
    null,
    {"name": "no request", "request": null},
    {"name": "f", "request": {"method": "GET", "url": "{{baseUrl}}/f"}}
  ],
  "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "{{token}}"}]},
  "variable": [{"key": "baseUrl", "value": "https://api.example.test"}, {"key": "token", "value": "col-tok"}]
}`

func TestStream_TrailingAuthAndVariables(t *testing.T) {
	order, auth, f := parseData(t, trailingBlocks)
	assert.Equal(t, []string{"/a", "/b", "/c", "/d", "/e", "/f"}, order)

	basic := "Basic dTpw" // base64("u:p")
	assert.Equal(t, "Bearer col-tok", auth["/a"], "collection auth declared after the items")
	assert.Equal(t, basic, auth["/b"], "folder auth declared after its items, inherited two levels down")
	assert.Empty(t, auth["/c"], "request noauth wins")
	assert.Equal(t, basic, auth["/d"])
	assert.Equal(t, "Bearer leaf", auth["/e"], "item-level auth after the request")
	assert.Equal(t, "Bearer col-tok", auth["/f"], "index paths stay aligned past null items")
	assert.Equal(t, 6, f.Stats().Emitted)

	n, err := New().Count(writeTestFile(t, trailingBlocks))
	require.NoError(t, err)
	assert.Equal(t, int64(6), n)
}

func TestStream_WrappedWithTrailingBlocks(t *testing.T) {
	data := `{"collection": {"item": [{"name": "a", "request": {"method": "GET", "url": "{{host}}/a"}}],
		"variable": [{"key": "host", "value": "http://wrapped.example.test"}],
		"auth": {"type": "apikey", "apikey": [{"key": "key", "value": "X-Key"}, {"key": "value", "value": "k"}]}},
		"item": [{"name": "ignored", "request": {"method": "GET", "url": "http://top.example.test/z"}}]}`
	f := New()
	var got []*httpmsg.HttpRequestResponse
	require.NoError(t, f.ParseFromData([]byte(data), func(rr *httpmsg.HttpRequestResponse) bool {
		got = append(got, rr)
		return true
	}))
	require.Len(t, got, 1)
	assert.Equal(t, "wrapped.example.test", got[0].Request().Header("Host"))
	assert.Equal(t, "k", got[0].Request().Header("X-Key"))

	n, err := New().Count(writeTestFile(t, data))
	require.NoError(t, err)
	assert.Equal(t, int64(1), n, "Count follows the same wrapped/unwrapped choice as Parse")

	// An empty wrapped collection falls back to the top-level items.
	empty := `{"collection": {"item": []}, "item": [{"name": "t", "request": {"method": "GET", "url": "http://top.example.test/t"}}]}`
	order, _, _ := parseData(t, empty)
	assert.Equal(t, []string{"/t"}, order)
}

func TestStream_EarlyStopAcrossFolders(t *testing.T) {
	calls := 0
	err := New().ParseFromData([]byte(trailingBlocks), func(*httpmsg.HttpRequestResponse) bool {
		calls++
		return calls < 2 // stop on /b, inside a nested folder
	})
	require.NoError(t, err)
	assert.Equal(t, 2, calls)
}

func TestStream_MalformedFailsBeforeEmitting(t *testing.T) {
	for _, data := range []string{
		`[]`,
		`{"item": {}}`,
		`{"item": [` + `{"name": "a", "request": {"method": "GET", "url": "http://e.test/a"}}` + `]} trailing`,
		`{"item": [` + `{"name": "a", "request": {"method": "GET", "url": "http://e.test/a"}}`, // truncated
	} {
		calls := 0
		err := New().ParseFromData([]byte(data), func(*httpmsg.HttpRequestResponse) bool { calls++; return true })
		assert.Error(t, err, data)
		assert.Zero(t, calls, "the prescan rejects the document before any request is emitted: %s", data)
	}
}

func TestStream_BOMAndNull(t *testing.T) {
	order, _, _ := parseData(t, "\xef\xbb\xbf"+testCollection)
	assert.Equal(t, []string{"/api/users", "/api/users"}, order)

	order, _, _ = parseData(t, `null`)
	assert.Empty(t, order)
}

// writeSyntheticCollection writes a collection of at least size bytes: folders
// of requests with raw bodies and saved example responses, with the collection
// auth and variables at the end as Postman writes them.
func writeSyntheticCollection(tb testing.TB, path string, size int64) int {
	tb.Helper()
	fh, err := os.Create(path)
	require.NoError(tb, err)
	defer func() { require.NoError(tb, fh.Close()) }()
	w := bufio.NewWriterSize(fh, 1<<20)

	example := strings.Repeat("example response line\\n", 100)
	_, _ = w.WriteString(`{"info":{"name":"G8 synthetic"},"item":[`)
	var written int64
	requests := 0
	for folder := 0; written < size; folder++ {
		if folder > 0 {
			_ = w.WriteByte(',')
		}
		k, _ := fmt.Fprintf(w, `{"name":"folder %d","item":[`, folder)
		written += int64(k)
		for i := range 50 {
			if i > 0 {
				_ = w.WriteByte(',')
			}
			k, _ = fmt.Fprintf(w, `{"name":"r%d","request":{"method":"POST","header":[{"key":"Content-Type","value":"application/json"}],`+
				`"body":{"mode":"raw","raw":"{\"id\":%d}"},"url":{"raw":"{{baseUrl}}/f%d/r%d"}},`+
				`"response":[{"name":"ok","code":200,"body":"%s"}]}`, i, i, folder, i, example)
			written += int64(k)
			requests++
		}
		_, _ = w.WriteString(`],"auth":{"type":"bearer","bearer":[{"key":"token","value":"f"}]}}`)
	}
	_, _ = w.WriteString(`],"variable":[{"key":"baseUrl","value":"https://api.example.test"}]}`)
	require.NoError(tb, w.Flush())
	return requests
}

func TestLargeCollectionBoundedMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("writes and parses a 100 MB collection")
	}
	const heapLimit = 64 << 20
	path := filepath.Join(t.TempDir(), "large.json")
	requests := writeSyntheticCollection(t, path, 100<<20)

	n, err := New().Count(path)
	require.NoError(t, err)
	assert.Equal(t, int64(requests), n)

	runtime.GC()
	var peak uint64
	sample := func() {
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		peak = max(peak, ms.HeapAlloc)
	}
	parsed := 0
	require.NoError(t, New().Parse(path, func(rr *httpmsg.HttpRequestResponse) bool {
		parsed++
		if parsed%256 == 0 {
			sample()
		}
		return true
	}))
	sample()
	assert.Equal(t, requests, parsed)
	t.Logf("Parse: %d requests, peak heap %d MB", parsed, peak>>20)
	assert.Less(t, peak, uint64(heapLimit))
}
