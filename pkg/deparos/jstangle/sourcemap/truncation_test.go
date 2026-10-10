package sourcemap

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildMap renders a v3 map whose sources are vendor or app files, each with
// contentBytes of embedded content. vendorFirst puts the vendor block first in
// index order, the way webpack lays out most real maps.
func buildMap(t testing.TB, app, vendor, contentBytes int, vendorFirst bool) []byte {
	t.Helper()
	type entry struct{ path, content string }
	var appEntries, vendorEntries []entry
	body := strings.Repeat("x", max(0, contentBytes-16))
	for i := range app {
		appEntries = append(appEntries, entry{fmt.Sprintf("webpack:///./src/module%04d.ts", i), fmt.Sprintf("/*%06d*/%s", i, body)})
	}
	for i := range vendor {
		vendorEntries = append(vendorEntries, entry{
			fmt.Sprintf("webpack:///./node_modules/pkg%04d/index.js", i), fmt.Sprintf("/*v%05d*/%s", i, body),
		})
	}
	ordered := append(appEntries, vendorEntries...)
	if vendorFirst {
		ordered = append(vendorEntries, appEntries...)
	}
	doc := struct {
		Version        int      `json:"version"`
		Sources        []string `json:"sources"`
		SourcesContent []string `json:"sourcesContent"`
		Mappings       string   `json:"mappings"`
	}{Version: 3, Mappings: "AAAA"}
	for _, e := range ordered {
		doc.Sources = append(doc.Sources, e.path)
		doc.SourcesContent = append(doc.SourcesContent, e.content)
	}
	out, err := json.Marshal(doc)
	require.NoError(t, err)
	return out
}

func TestParse_TruncatesManySourcesAppFirst(t *testing.T) {
	// 2000 sources, 1800 of them vendor and listed first: the old parser
	// rejected the whole map at source 513, so no module reported it.
	content := buildMap(t, 200, 1800, 64, true)

	document, err := Parse(content, "https://app.example.test/static/js/main.js")
	require.NoError(t, err)

	assert.True(t, document.Truncated)
	assert.Equal(t, TruncationSourceCount, document.TruncationReason)
	assert.Equal(t, 2000, document.SourcesTotal)
	assert.Len(t, document.SourcePaths, 2000, "every path is still listed")
	require.Len(t, document.Sources, MaxSources)
	assert.Equal(t, 2000-MaxSources, document.SkippedSources)
	assert.Equal(t, 2000-MaxSources, document.SkippedVendor, "only vendor sources were dropped")

	app := 0
	for _, source := range document.Sources {
		if strings.HasPrefix(source.Path, "src/") {
			app++
		}
	}
	assert.Equal(t, 200, app, "all application sources are recovered")
}

func TestParse_AggregateBudgetPrefersAppSources(t *testing.T) {
	// 40 vendor + 20 app sources of 256 KiB each: 15 MiB of content against an
	// 8 MiB budget. Every app source must fit before any vendor source.
	content := buildMap(t, 20, 40, 256*1024, true)

	document, err := Parse(content, "https://app.example.test/main.js")
	require.NoError(t, err)
	assert.True(t, document.Truncated)
	assert.Equal(t, TruncationAggregateSize, document.TruncationReason)
	assert.Equal(t, 60, document.SourcesTotal)

	total, app := 0, 0
	for _, source := range document.Sources {
		total += len(source.Content)
		if strings.HasPrefix(source.Path, "src/") {
			app++
		}
	}
	assert.LessOrEqual(t, total, MaxAggregateSourceBytes)
	assert.Equal(t, 20, app)
	assert.Equal(t, document.SkippedSources, document.SkippedVendor)
	assert.Equal(t, 60-len(document.Sources), document.SkippedSources)
}

func TestParse_LargeMapUnderSizeCap(t *testing.T) {
	// ~20 MiB: over the old 8 MiB document cap, under the new one.
	content := buildMap(t, 100, 220, 64*1024, false)
	require.Greater(t, len(content), 16*1024*1024)
	require.Less(t, len(content), MaxMapBytes)

	document, err := Parse(content, "https://app.example.test/main.js")
	require.NoError(t, err)
	assert.True(t, document.HasMappings)
	assert.True(t, document.Truncated)
	assert.Len(t, document.SourcePaths, 320)
}

func TestParse_OversizedSingleSourceIsSkippedNotFatal(t *testing.T) {
	big := strings.Repeat("a", MaxSourceContentBytes+1)
	raw := fmt.Sprintf(`{"version":3,"sources":["src/big.js","src/small.js"],"sourcesContent":[%q,"ok"],"mappings":"AAAA"}`, big)

	document, err := Parse([]byte(raw), "https://app.example.test/main.js")
	require.NoError(t, err)
	require.Len(t, document.Sources, 1)
	assert.Equal(t, "src/small.js", document.Sources[0].Path)
	assert.True(t, document.Truncated)
	assert.Equal(t, TruncationSourceSize, document.TruncationReason)
	assert.Equal(t, 1, document.SkippedSources)
	assert.Equal(t, 0, document.SkippedVendor)
}

func TestParse_UntruncatedMapReportsNoTruncation(t *testing.T) {
	document, err := Parse([]byte(minimalMap), "https://app.example.test/main.js")
	require.NoError(t, err)
	assert.False(t, document.Truncated)
	assert.Empty(t, document.TruncationReason)
	assert.Equal(t, 1, document.SourcesTotal)
	assert.Zero(t, document.SkippedSources)
}

func TestParse_EscapedContentAndKeys(t *testing.T) {
	raw := `{"version":3,"sources":["src/a.js"],"sourcesContent":["line1\nline2 \"q\" é"],"mappings":"AAAA","names":[1,true,null,{"x":[]}]}`
	document, err := Parse([]byte(raw), "https://app.example.test/main.js")
	require.NoError(t, err)
	require.Len(t, document.Sources, 1)
	assert.Equal(t, "line1\nline2 \"q\" é", string(document.Sources[0].Content))
}

func TestParse_MalformedJSONRejected(t *testing.T) {
	for _, raw := range []string{
		`{"version":3,"sources":["a.js"],"mappings":"AAAA"`,
		`{"version":3,"sources":["a.js"] "mappings":"AAAA"}`,
		`{"version":3,"sources":["a.js],"mappings":"AAAA"}`,
		`{"version":3} trailing`,
		`{"version":tru}`,
		strings.Repeat("[", 1000),
	} {
		_, err := Parse([]byte(raw), "https://app.example.test/main.js")
		assert.Error(t, err, raw)
	}
}

func TestIsVendorPath(t *testing.T) {
	for _, vendor := range []string{
		"node_modules/react/index.js", "app/node_modules/x.js", "webpack/bootstrap 1234",
		"(webpack)/buildin/global.js", "~/lodash/lodash.js", ".pnpm/react@18/node_modules/react/x.js",
		"vite/preload-helper", "bower_components/jquery/jquery.js",
	} {
		assert.True(t, IsVendorPath(vendor), vendor)
	}
	for _, app := range []string{"src/App.tsx", "app/services/api.ts", "lib/invite.ts"} {
		assert.False(t, IsVendorPath(app), app)
	}
}

// BenchmarkParseLargeMap parses a ~30 MiB map, mostly vendor sourcesContent.
// Run with -benchmem: allocation per op should stay near the 8 MiB recovered
// budget plus bookkeeping, not a second copy of the document.
func BenchmarkParseLargeMap(b *testing.B) {
	content := buildMap(b, 300, 1200, 20*1024, true)
	if len(content) < 28*1024*1024 || len(content) > MaxMapBytes {
		b.Fatalf("fixture is %d bytes, want ~30 MiB", len(content))
	}
	b.SetBytes(int64(len(content)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		document, err := Parse(content, "https://app.example.test/main.js")
		if err != nil || !document.Truncated {
			b.Fatalf("parse: err=%v truncated=%v", err, document != nil && document.Truncated)
		}
	}
}
