package discovery

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/payload"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/tracker"
	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
)

// TestIsReferencedProvenance pins the label fallback the prefix breaker uses for
// task types that do not track their own provenance.
func TestIsReferencedProvenance(t *testing.T) {
	referenced := []string{"spider", "js-extracted", "form", "redirect"}
	for _, fb := range referenced {
		assert.True(t, isReferencedProvenance(fb), "%q is an application reference", fb)
	}

	guessed := []string{
		// "jsfetch" is deliberately absent: that queue carries guesses too, so
		// JSFetchTask answers via IsReferenced rather than through this label.
		"jsfetch",
		"fuzzer", "numeric", "ext-variant", "malformed-path-probe", "casesense",
		"short-file-no-ext", "short-dir", "long-dir", "wordlist", "observed",
		"", "something-new",
	}
	for _, fb := range guessed {
		assert.False(t, isReferencedProvenance(fb), "%q is a guess", fb)
	}
}

// provenanceTask is a minimal Task whose only meaningful property is its
// provenance label — the one input sendWorkItem's breaker exemption reads.
type provenanceTask struct {
	foundBy string
}

func (t *provenanceTask) Hash() uint64                      { return 1 }
func (t *provenanceTask) Priority() uint8                   { return 0 }
func (t *provenanceTask) Description() string               { return "provenance stub" }
func (t *provenanceTask) FoundByName() string               { return t.foundBy }
func (t *provenanceTask) FullURL() []byte                   { return nil }
func (t *provenanceTask) Extension() string                 { return "" }
func (t *provenanceTask) Depth() uint16                     { return 0 }
func (t *provenanceTask) IsFromSpider() bool                { return false }
func (t *provenanceTask) PayloadProvider() payload.Provider { return nil }
func (t *provenanceTask) Expand(context.Context, func(string, uint16)) error {
	return nil
}

// TestSendWorkItem_PrefixBreakerExemptsReferencedAssets is the regression for the
// bug that made the whole source-map pipeline dead code: /static trips the
// breaker after a dozen 404 guesses, and the bundle's own .js.map — an asset the
// application explicitly references — was dropped with them.
//
// The second half pins the other direction: JSFetchTask carries guesses too (the
// bundle-name sweep, the sibling .map probe), and those must stay gated.
func TestSendWorkItem_PrefixBreakerExemptsReferencedAssets(t *testing.T) {
	breaker := tracker.NewPrefixBreaker(tracker.BreakerConfig{
		Enabled: true, MinSamples: 2, TripRatio: 0.9, PrefixSegments: 1, LengthBucket: 256,
	})
	// Trip /static with uniform 404s, exactly as a wordlist sweep does.
	dead, _ := url.Parse("http://example.test/static/nope-1")
	for i := 0; i < 4; i++ {
		breaker.Observe(dead, 404, "text/html", 120)
	}
	require.True(t, breaker.IsDead(dead), "prefix must be tripped for the test to mean anything")

	coordinator := &PayloadCoordinator{
		callbacks: &Callbacks{PrefixBreaker: breaker},
		workChan:  make(chan *WorkItem, 4),
	}

	mapURL := "http://example.test/static/js/main.abc123.chunk.js.map"
	referenced := NewJSFetchTask(&JSFetchTaskConfig{JSURLs: []string{mapURL}, Provenance: ProvenanceReferenced})
	coordinator.sendWorkItem(context.Background(), referenced, mapURL, 0)
	select {
	case item := <-coordinator.workChan:
		assert.Equal(t, mapURL, item.URL, "a referenced asset must survive a tripped prefix")
	default:
		t.Fatal("referenced asset was dropped by the prefix breaker")
	}

	// A JSFetchTask carrying guesses (bundle sweep, sibling .map probe) must stay
	// gated — the task type alone cannot earn the exemption.
	guessURL := "http://example.test/static/js/main.js.map"
	guessed := NewJSFetchTask(&JSFetchTaskConfig{JSURLs: []string{guessURL}, Provenance: ProvenanceGuessed})
	coordinator.sendWorkItem(context.Background(), guessed, guessURL, 0)
	select {
	case item := <-coordinator.workChan:
		t.Fatalf("guessed JS fetch %q must stay suppressed under a tripped prefix", item.URL)
	default:
	}

	// And an ordinary brute-force task, via the label fallback.
	coordinator.sendWorkItem(context.Background(), &provenanceTask{foundBy: "fuzzer"}, "http://example.test/static/admin", 0)
	select {
	case item := <-coordinator.workChan:
		t.Fatalf("guessed path %q must stay suppressed under a tripped prefix", item.URL)
	default:
	}
}

// TestJSFetchTaskHashSeparatesProvenance: the same URL reached as a reference and
// as a guess faces different gates, so the queue must not collapse them.
func TestJSFetchTaskHashSeparatesProvenance(t *testing.T) {
	urls := []string{"http://example.test/static/js/app.js.map"}
	referenced := NewJSFetchTask(&JSFetchTaskConfig{JSURLs: urls, Provenance: ProvenanceReferenced})
	guessed := NewJSFetchTask(&JSFetchTaskConfig{JSURLs: urls, Provenance: ProvenanceGuessed})
	assert.NotEqual(t, referenced.Hash(), guessed.Hash())
	assert.True(t, referenced.IsReferenced())
	assert.False(t, guessed.IsReferenced())
}

// TestProcessSourceMapLeads_ParsesMapWhateverFetchedIt covers the second drop:
// source-map handling now sits above the task-type dispatch, so the link
// extractor winning the shared RequestCache no longer costs the parse.
func TestProcessSourceMapLeads_ParsesMapWhateverFetchedIt(t *testing.T) {
	const body = `{"version":3,"sources":["src/App.tsx"],"sourcesContent":["const x = 1;"],"mappings":"AAAA"}`

	tests := []struct {
		name       string
		path       string
		status     int
		body       string
		wantCalled bool
	}{
		{"map is parsed", "/static/js/app.js.map", 200, body, true},
		{"uppercase extension is parsed", "/static/js/app.js.MAP", 200, body, true},
		{"non-map path is ignored", "/static/js/app.js", 200, body, false},
		{"404 is ignored", "/static/js/app.js.map", 404, body, false},
		{"empty body is ignored", "/static/js/app.js.map", 200, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tt.status,
				Header:     http.Header{"Content-Type": []string{"application/octet-stream"}},
				Body:       io.NopCloser(strings.NewReader(tt.body)),
			}
			rc := responsechain.NewResponseChain(resp, 0)
			require.NoError(t, rc.Fill())
			defer rc.Close()

			var gotURL string
			var gotBody []byte
			coordinator := &PayloadCoordinator{callbacks: &Callbacks{
				ProcessSourceMap: func(_ context.Context, mapURL *url.URL, content []byte) {
					gotURL = mapURL.String()
					gotBody = content
				},
			}}

			target, err := url.Parse("http://example.test" + tt.path)
			require.NoError(t, err)
			coordinator.processSourceMapLeads(context.Background(), target, rc, coordinator.callbacks)

			if !tt.wantCalled {
				assert.Empty(t, gotURL, "parser must not be invoked")
				return
			}
			assert.True(t, strings.HasSuffix(strings.ToLower(gotURL), ".map"), "parser got %q", gotURL)
			assert.Equal(t, tt.body, string(gotBody))
		})
	}
}
