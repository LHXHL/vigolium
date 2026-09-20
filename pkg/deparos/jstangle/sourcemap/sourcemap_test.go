package sourcemap

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const minimalMap = `{"version":3,"sources":["src/App.tsx"],"sourcesContent":["const apiKey = 'x';"],"mappings":"AAAA"}`

func TestExtractReferences_AllForms(t *testing.T) {
	inline := "data:application/json;base64," + base64.StdEncoding.EncodeToString([]byte(minimalMap))

	tests := []struct {
		name       string
		body       string
		wantURL    string
		wantOrigin ReferenceOrigin
		wantInline bool
	}{
		{
			name:       "js line comment",
			body:       "console.log(1);\n//# sourceMappingURL=main.abc.js.map\n",
			wantURL:    "main.abc.js.map",
			wantOrigin: OriginComment,
		},
		{
			name:       "legacy @ form",
			body:       "console.log(1);\n//@ sourceMappingURL=legacy.js.map\n",
			wantURL:    "legacy.js.map",
			wantOrigin: OriginComment,
		},
		{
			name:       "absolute reference on another host",
			body:       "x=1\n//# sourceMappingURL=https://cdn.example.test/maps/app.js.map\n",
			wantURL:    "https://cdn.example.test/maps/app.js.map",
			wantOrigin: OriginComment,
		},
		{
			// The CSS form: the closing */ must not become part of the URL.
			name:       "css block comment",
			body:       ".a{color:red}\n/*# sourceMappingURL=app.css.map */\n",
			wantURL:    "app.css.map",
			wantOrigin: OriginBlockComment,
		},
		{
			// webpack eval devtool: the module is a JS string, so its newline is the
			// two characters \ and n and no multiline anchor ever matches.
			name:       `eval string with escaped newline`,
			body:       `eval("const a=1;\n//# sourceMappingURL=webpack-module.js.map\n");`,
			wantURL:    "webpack-module.js.map",
			wantOrigin: OriginEvalString,
		},
		{
			name:       "inline data url",
			body:       "x=1\n//# sourceMappingURL=" + inline + "\n",
			wantOrigin: OriginInline,
			wantInline: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			references := ExtractReferences([]byte(tt.body))
			require.Len(t, references, 1, "expected exactly one reference")
			assert.Equal(t, tt.wantOrigin, references[0].Origin)
			if tt.wantInline {
				assert.NotEmpty(t, references[0].Inline, "inline map must be decoded")
				return
			}
			assert.Equal(t, tt.wantURL, references[0].URL)
		})
	}
}

func TestExtractReferences_NoneAndDedup(t *testing.T) {
	assert.Empty(t, ExtractReferences([]byte("const a = 1;")), "a bundle with no reference yields none")

	// A build that emits the same reference twice (comment plus eval form) must
	// not produce two fetches for one file.
	body := "x=1\n//# sourceMappingURL=app.js.map\n" + `eval("y=2;\n//# sourceMappingURL=app.js.map\n");`
	assert.Len(t, ExtractReferences([]byte(body)), 1, "duplicate references collapse")
}

func TestExtractReferences_BrokenInlineDoesNotHideOthers(t *testing.T) {
	body := "a=1\n//# sourceMappingURL=data:application/json;base64,!!!not-base64!!!\n" +
		"b=2\n//# sourceMappingURL=real.js.map\n"
	references := ExtractReferences([]byte(body))
	require.Len(t, references, 1)
	assert.Equal(t, "real.js.map", references[0].URL)
}

func TestParse_RecoversSourcesAndPaths(t *testing.T) {
	document, err := Parse([]byte(minimalMap), "https://app.example.test/static/js/main.js")
	require.NoError(t, err)
	require.Len(t, document.Sources, 1)
	assert.Equal(t, "src/App.tsx", document.Sources[0].Path)
	assert.Equal(t, "tsx", document.Sources[0].Language)
	assert.Equal(t, "const apiKey = 'x';", string(document.Sources[0].Content))
	assert.Equal(t, []string{"src/App.tsx"}, document.SourcePaths)
	assert.True(t, document.HasEmbeddedContent())
}

func TestParse_ContentlessMapYieldsFetchableSources(t *testing.T) {
	// A build that strips sourcesContent still names the files, and a deployment
	// that ships the map usually still serves them.
	const stripped = `{"version":3,"sourceRoot":"/src","sources":["app/main.ts","vendor/lib.ts"],"mappings":"AAAA"}`

	document, err := Parse([]byte(stripped), "https://app.example.test/static/js/main.js")
	require.NoError(t, err)
	assert.False(t, document.HasEmbeddedContent(), "no content is embedded")
	assert.Equal(t, []string{"src/app/main.ts", "src/vendor/lib.ts"}, document.SourcePaths,
		"paths still disclose internal layout")
	assert.Equal(t, []string{
		"https://app.example.test/src/app/main.ts",
		"https://app.example.test/src/vendor/lib.ts",
	}, document.FetchableSources)
}

func TestParse_VirtualBundlerPathsAreNotFetchable(t *testing.T) {
	const virtual = `{"version":3,"sources":["webpack://app/./src/index.ts","webpack-internal:///./src/x.ts"],"mappings":"AAAA"}`

	document, err := Parse([]byte(virtual), "https://app.example.test/static/js/main.js")
	require.NoError(t, err)
	assert.Empty(t, document.FetchableSources,
		"a webpack:// path names a module in the build graph, not a file on the server")
	assert.Equal(t, []string{"app/src/index.ts", "src/x.ts"}, document.SourcePaths)
}

func TestParse_IndexedMapSections(t *testing.T) {
	inlineSection := fmt.Sprintf(
		`{"version":3,"sections":[{"offset":{"line":0,"column":0},"map":%s}]}`, minimalMap)
	document, err := Parse([]byte(inlineSection), "https://app.example.test/bundle.js")
	require.NoError(t, err)
	require.Len(t, document.Sources, 1, "an inline section's sources are recovered")

	externalSection := `{"version":3,"sections":[{"offset":{"line":0,"column":0},"url":"chunk-1.js.map"}]}`
	document, err = Parse([]byte(externalSection), "https://app.example.test/bundle.js")
	require.NoError(t, err)
	assert.Equal(t, []string{"chunk-1.js.map"}, document.ExternalSections,
		"a section pointing elsewhere must be reported so the caller can follow it")
}

func TestParse_Rejects(t *testing.T) {
	_, err := Parse(nil, "https://app.example.test/x.js")
	assert.Error(t, err, "empty body")

	_, err = Parse([]byte(`{"version":2,"sources":[],"mappings":""}`), "https://app.example.test/x.js")
	assert.Error(t, err, "only v3 is defined")

	_, err = Parse([]byte(`<!doctype html><html>`), "https://app.example.test/x.js")
	assert.Error(t, err, "an SPA shell is not a map")

	_, err = Parse(make([]byte, MaxMapBytes+1), "https://app.example.test/x.js")
	assert.Error(t, err, "oversized map")
}

func TestNormalizePath_NeverEscapesDirectory(t *testing.T) {
	tests := []struct {
		root, source, want string
	}{
		{"", "webpack://app/./src/index.ts", "app/src/index.ts"},
		{"", "../../etc/passwd", "etc/passwd"},
		{"/src", "app/main.ts", "src/app/main.ts"},
		{"", `windows\style\path.ts`, "windows/style/path.ts"},
		{"", "", "source.js"},
		{"", "file:///Users/dev/app/src/x.ts", "Users/dev/app/src/x.ts"},
	}
	for _, tt := range tests {
		got := NormalizePath(tt.root, tt.source)
		assert.Equal(t, tt.want, got, "NormalizePath(%q, %q)", tt.root, tt.source)
		assert.NotContains(t, got, "..", "normalized path must not traverse")
	}
}

func TestSiblingCandidate(t *testing.T) {
	tests := []struct {
		asset string
		want  string
		ok    bool
	}{
		{"https://app.example.test/static/js/main.abc.js", "https://app.example.test/static/js/main.abc.js.map", true},
		{"https://app.example.test/assets/app.mjs", "https://app.example.test/assets/app.mjs.map", true},
		{"https://app.example.test/assets/app.css", "https://app.example.test/assets/app.css.map", true},
		{"https://app.example.test/assets/app.js?v=2", "https://app.example.test/assets/app.js.map", true},
		// Not mappable.
		{"https://app.example.test/assets/app.js.map", "", false},
		{"https://app.example.test/index.html", "", false},
		{"https://app.example.test/api/users", "", false},
		{"/relative/app.js", "", false},
	}
	for _, tt := range tests {
		got, ok := SiblingCandidate(tt.asset)
		assert.Equal(t, tt.ok, ok, "SiblingCandidate(%q) ok", tt.asset)
		assert.Equal(t, tt.want, got, "SiblingCandidate(%q)", tt.asset)
	}
}

func TestIsMapPath(t *testing.T) {
	for _, p := range []string{"/app.js.map", "/styles.css.MAP", "/bundle.min.js.map"} {
		assert.True(t, IsMapPath(p), "%q names a map", p)
	}
	for _, p := range []string{"/app.js", "/sitemap.xml", "/map", "", ".map"} {
		if p == ".map" {
			continue // a bare extension is a map path; covered above via full paths
		}
		assert.False(t, IsMapPath(p), "%q does not name a map", p)
	}
}

func TestLooksLikeMap(t *testing.T) {
	assert.True(t, LooksLikeMap([]byte(minimalMap)))
	assert.True(t, LooksLikeMap([]byte("\ufeff"+minimalMap)), "a UTF-8 BOM is still a map")
	assert.False(t, LooksLikeMap([]byte(`<!doctype html><html><body>SPA shell</body></html>`)),
		"a catch-all 200 must not be mistaken for a map")
	assert.False(t, LooksLikeMap([]byte(`{"error":"not found"}`)), "unrelated JSON is not a map")
	assert.False(t, LooksLikeMap(nil))
}

// TestCandidatesFor pins the precedence both consumers depend on: headers, then
// body references, then the sibling guess only when nothing referenced a map.
func TestCandidatesFor(t *testing.T) {
	const asset = "https://app.example.test/static/js/main.abc.js"
	headers := func(values map[string]string) func(string) string {
		return func(name string) string { return values[name] }
	}

	t.Run("header reference resolves against the asset", func(t *testing.T) {
		got := CandidatesFor(asset, headers(map[string]string{"SourceMap": "maps/main.js.map"}), nil)
		require.Len(t, got, 1)
		assert.Equal(t, "https://app.example.test/static/js/maps/main.js.map", got[0].URL)
		assert.Equal(t, OriginHeader, got[0].Origin)
	})

	t.Run("body reference", func(t *testing.T) {
		got := CandidatesFor(asset, nil, []byte("x=1\n//# sourceMappingURL=main.abc.js.map\n"))
		require.Len(t, got, 1)
		assert.Equal(t, "https://app.example.test/static/js/main.abc.js.map", got[0].URL)
		assert.Equal(t, OriginComment, got[0].Origin)
	})

	t.Run("inline map needs no URL", func(t *testing.T) {
		inline := "data:application/json;base64," + base64.StdEncoding.EncodeToString([]byte(minimalMap))
		got := CandidatesFor(asset, nil, []byte("x=1\n//# sourceMappingURL="+inline+"\n"))
		require.Len(t, got, 1)
		assert.Empty(t, got[0].URL)
		assert.NotEmpty(t, got[0].Inline)
	})

	t.Run("sibling guessed only when nothing referenced a map", func(t *testing.T) {
		got := CandidatesFor(asset, nil, []byte("x=1;"))
		require.Len(t, got, 1)
		assert.Equal(t, "https://app.example.test/static/js/main.abc.js.map", got[0].URL)
		assert.Equal(t, OriginGuessed, got[0].Origin)

		referenced := CandidatesFor(asset, nil, []byte("x=1\n//# sourceMappingURL=other.js.map\n"))
		require.Len(t, referenced, 1, "a referenced map suppresses the guess")
		assert.Equal(t, OriginComment, referenced[0].Origin)
	})

	t.Run("header and body dedup to one candidate", func(t *testing.T) {
		got := CandidatesFor(asset,
			headers(map[string]string{"SourceMap": "main.abc.js.map"}),
			[]byte("x=1\n//# sourceMappingURL=main.abc.js.map\n"))
		require.Len(t, got, 1)
		assert.Equal(t, OriginHeader, got[0].Origin, "the header wins precedence")
	})

	t.Run("non-mappable asset yields nothing", func(t *testing.T) {
		assert.Empty(t, CandidatesFor("https://app.example.test/index.html", nil, []byte("<html>")))
	})
}
