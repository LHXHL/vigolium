package har

import (
	"bufio"
	"encoding/base64"
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

func collectURLs(t *testing.T, data string) ([]string, error) {
	t.Helper()
	var urls []string
	err := New().ParseFromData([]byte(data), func(rr *httpmsg.HttpRequestResponse) bool {
		u, err := rr.URL()
		require.NoError(t, err)
		urls = append(urls, u.String())
		return true
	})
	return urls, err
}

const streamEntry = `{"request":{"method":"GET","url":"https://example.com/%s","headers":[]},"response":{"status":200,"headers":[],"content":{"text":"ok"}}}`

func TestStream_KeyOrderAndCase(t *testing.T) {
	// entries before version, a large `pages` block first, mixed-case keys
	// (json.Unmarshal matched fields case-insensitively) and unknown members.
	data := `{"Log":{"pages":[{"id":"p","title":{"nested":[1,2,{"x":null}]}}],` +
		`"ENTRIES":[` + fmt.Sprintf(streamEntry, "a") + `,` + fmt.Sprintf(streamEntry, "b") + `],` +
		`"version":"1.2","creator":{"name":"x"}},"extra":[true,false]}`
	urls, err := collectURLs(t, data)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://example.com/a", "https://example.com/b"}, urls)
}

func TestStream_BOMAccepted(t *testing.T) {
	urls, err := collectURLs(t, "\xef\xbb\xbf"+testHAR)
	require.NoError(t, err)
	assert.Len(t, urls, 2)
}

func TestStream_NullAndEmpty(t *testing.T) {
	for _, data := range []string{`null`, `{}`, `{"log":null}`, `{"log":{"entries":null}}`, `{"log":{"entries":[]}}`} {
		urls, err := collectURLs(t, data)
		require.NoError(t, err, data)
		assert.Empty(t, urls, data)
	}
}

func TestStream_RejectsMalformed(t *testing.T) {
	for _, data := range []string{
		`[]`,
		`{"log":[]}`,
		`{"log":{"entries":{}}}`,
		`{"log":{"entries":[]}} trailing`,
		`{"log":{"entries":[{"request":{"method":"GET","url":"https://example.com/"}}`, // truncated
		`{"log":{"entries":[{"response":{"status":"200"}}]}}`,                          // type error
	} {
		_, err := collectURLs(t, data)
		assert.Error(t, err, data)
	}
}

func TestStream_EarlyStopReadsNoFurther(t *testing.T) {
	// Everything after the first entry is garbage; a callback that stops at the
	// first entry must never reach it.
	data := `{"log":{"entries":[` + fmt.Sprintf(streamEntry, "first") + `, !!! not json`
	calls := 0
	err := New().ParseFromData([]byte(data), func(*httpmsg.HttpRequestResponse) bool {
		calls++
		return false
	})
	require.NoError(t, err)
	assert.Equal(t, 1, calls)
}

func TestStream_TruncatedTailKeepsEarlierEntries(t *testing.T) {
	data := `{"log":{"entries":[` + fmt.Sprintf(streamEntry, "a") + `,{"request":`
	urls, err := collectURLs(t, data)
	require.Error(t, err)
	assert.Equal(t, []string{"https://example.com/a"}, urls)
}

func TestCount_MatchesFixturesAndSkipsUnbuildable(t *testing.T) {
	for _, name := range []string{"chrome_h2.har", "firefox.har"} {
		path := filepath.Join("testdata", name)
		n, err := New().Count(path)
		require.NoError(t, err, name)

		parsed := 0
		require.NoError(t, New().Parse(path, func(*httpmsg.HttpRequestResponse) bool { parsed++; return true }))
		assert.Positive(t, n, name)
		assert.GreaterOrEqual(t, n, int64(parsed), name)
	}

	// Count counts entries, including ones Parse later drops.
	path := filepath.Join(t.TempDir(), "x.har")
	require.NoError(t, os.WriteFile(path, []byte(`{"log":{"entries":[{},`+fmt.Sprintf(streamEntry, "a")+`]}}`), 0o644))
	n, err := New().Count(path)
	require.NoError(t, err)
	assert.Equal(t, int64(2), n)

	_, err = New().Count(filepath.Join(t.TempDir(), "missing.har"))
	assert.Error(t, err)
}

// --- large archive: bounded memory ---

// writeSyntheticHAR writes a HAR of at least size bytes whose entries carry a
// base64 response body and a JSON request body, and returns the entry count.
func writeSyntheticHAR(tb testing.TB, path string, size int64) int {
	tb.Helper()
	fh, err := os.Create(path)
	require.NoError(tb, err)
	defer func() { require.NoError(tb, fh.Close()) }()
	w := bufio.NewWriterSize(fh, 1<<20)

	body := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("<div>synthetic response body</div>\n", 128)))
	_, _ = w.WriteString(`{"log":{"version":"1.2","creator":{"name":"G8 synthetic","version":"1"},"pages":[],"entries":[`)
	var written int64
	n := 0
	for ; written < size; n++ {
		if n > 0 {
			_ = w.WriteByte(',')
		}
		k, _ := fmt.Fprintf(w, `{"startedDateTime":"2026-01-01T00:00:00Z","time":12,`+
			`"request":{"method":"POST","url":"https://app.example.test/api/items/%d?q=%d","httpVersion":"h2",`+
			`"headers":[{"name":":authority","value":"app.example.test"},{"name":"content-type","value":"application/json"},{"name":"cookie","value":"sid=%d"}],`+
			`"queryString":[{"name":"q","value":"%d"}],"postData":{"mimeType":"application/json","text":"{\"id\":%d,\"name\":\"item\"}"}},`+
			`"response":{"status":200,"statusText":"OK","httpVersion":"h2","headers":[{"name":"content-type","value":"text/html"},{"name":"content-encoding","value":"gzip"}],`+
			`"content":{"size":4480,"mimeType":"text/html","encoding":"base64","text":"%s"}},"cache":{},"timings":{"send":1,"wait":10,"receive":1}}`,
			n, n, n, n, n, body)
		written += int64(k)
	}
	_, _ = w.WriteString(`]}}`)
	require.NoError(tb, w.Flush())
	return n
}

// peakHeap samples HeapAlloc; sample is cheap enough to call every few hundred entries.
type peakHeap struct{ max uint64 }

func (p *peakHeap) sample() {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	if ms.HeapAlloc > p.max {
		p.max = ms.HeapAlloc
	}
}

// TestLargeHARBoundedMemory streams a 200 MB archive and checks the heap never
// approaches the file size: the old json.Unmarshal path held the file bytes
// plus every decoded entry (well over 400 MB) before emitting anything.
func TestLargeHARBoundedMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("writes and parses a 200 MB HAR")
	}
	const size = 200 << 20
	const heapLimit = 64 << 20

	path := filepath.Join(t.TempDir(), "large.har")
	entries := writeSyntheticHAR(t, path, size)

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	n, err := New().Count(path)
	require.NoError(t, err)
	assert.Equal(t, int64(entries), n)

	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	countAlloc := after.TotalAlloc - before.TotalAlloc
	t.Logf("Count: %d entries, %d MB allocated", n, countAlloc>>20)
	assert.Less(t, countAlloc, uint64(heapLimit), "Count must not materialise entries")

	runtime.GC()
	var peak peakHeap
	parsed := 0
	err = New().Parse(path, func(rr *httpmsg.HttpRequestResponse) bool {
		parsed++
		if parsed%256 == 0 {
			peak.sample()
		}
		return true
	})
	require.NoError(t, err)
	peak.sample()
	assert.Equal(t, entries, parsed)
	t.Logf("Parse: %d entries, peak heap %d MB", parsed, peak.max>>20)
	assert.Less(t, peak.max, uint64(heapLimit), "Parse heap must stay bounded by one entry, not the archive")
}

func BenchmarkParseSyntheticHAR(b *testing.B) {
	path := filepath.Join(b.TempDir(), "bench.har")
	writeSyntheticHAR(b, path, 16<<20)
	info, err := os.Stat(path)
	require.NoError(b, err)
	b.SetBytes(info.Size())
	b.ReportAllocs()
	for b.Loop() {
		if err := New().Parse(path, func(*httpmsg.HttpRequestResponse) bool { return true }); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCountSyntheticHAR(b *testing.B) {
	path := filepath.Join(b.TempDir(), "bench.har")
	writeSyntheticHAR(b, path, 16<<20)
	info, err := os.Stat(path)
	require.NoError(b, err)
	b.SetBytes(info.Size())
	b.ReportAllocs()
	for b.Loop() {
		if _, err := New().Count(path); err != nil {
			b.Fatal(err)
		}
	}
}
