//go:build integration

package action

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// webComponentPage wraps buttons in an open and a closed shadow root. The
// closed one has only an addEventListener handler, so only the pierced CDP
// listener pass can find it; the open one also matches the "button" click
// selector, so the selector pass and the listener pass must agree on one ID.
const webComponentPage = `<!doctype html><html><body>
	<a href="#top">top</a>
	<x-open></x-open>
	<x-closed></x-closed>
	<div id="card" style="padding:4px">card</div>
	<script>
		document.getElementById('card').addEventListener('click', () => {});
		customElements.define('x-open', class extends HTMLElement {
			connectedCallback() {
				const sr = this.attachShadow({mode: 'open'});
				sr.innerHTML = '<button>Open</button>';
				sr.querySelector('button').addEventListener('click', () => {});
			}
		});
		customElements.define('x-closed', class extends HTMLElement {
			connectedCallback() {
				const sr = this.attachShadow({mode: 'closed'});
				sr.innerHTML = '<div class="tile">Closed</div>';
				sr.querySelector('div').addEventListener('click', () => {});
			}
		});
	</script>
</body></html>`

func servePage(t testing.TB, html string) (*httptest.Server, *browser.Page) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(html))
	}))
	cfg, err := config.New(server.URL)
	if err != nil {
		server.Close()
		t.Fatalf("config: %v", err)
	}
	cfg.Headless = true
	b, err := browser.New(cfg)
	if err != nil {
		server.Close()
		t.Fatalf("browser: %v", err)
	}
	t.Cleanup(func() { b.Close(); server.Close() })
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("page: %v", err)
	}
	if err := page.Navigate(server.URL); err != nil {
		t.Fatalf("navigate: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	return server, page
}

// TestExtractPiercesShadowRoots checks the extractor's output identities: light
// DOM keeps bare XPaths, the open-root button and the closed-root tile are
// HowLocator candidates, and each element appears exactly once.
func TestExtractPiercesShadowRoots(t *testing.T) {
	server, page := servePage(t, webComponentPage)
	cfg, _ := config.New(server.URL)
	ext := NewCandidateElementExtractor(cfg)

	cands, err := ext.Extract(context.Background(), page)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	ids := map[string]int{}
	for _, c := range cands {
		ids[string(c.Identification.How)+" "+c.Identification.Value]++
	}
	want := []string{
		"xpath /html[1]/body[1]/a[1]",
		"xpath /html[1]/body[1]/div[1]",
		`locator {"hostChain":["/html[1]/body[1]/x-open[1]"],"innerXPath":"/button[1]"}`,
		`locator {"hostChain":["/html[1]/body[1]/x-closed[1]"],"innerXPath":"/div[1]"}`,
	}
	for _, w := range want {
		if ids[w] != 1 {
			t.Errorf("candidate %q seen %d times, want 1 (all: %v)", w, ids[w], ids)
		}
	}
	for id, n := range ids {
		if strings.Contains(id, "data-vgo-uid") {
			t.Errorf("shadow candidate still identified by a uid tag: %s", id)
		}
		if n > 1 {
			t.Errorf("duplicate candidate %s (%d)", id, n)
		}
	}
}

// TestExtractListenerCap confirms max_listener_probe_nodes bounds the CDP pass.
func TestExtractListenerCap(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`<!doctype html><html><body>`)
	for i := 0; i < 30; i++ {
		fmt.Fprintf(&sb, `<div class="c">%d</div>`, i)
	}
	sb.WriteString(`<script>document.querySelectorAll('.c').forEach(d => d.addEventListener('click', () => {}));</script></body></html>`)
	server, page := servePage(t, sb.String())

	snap, err := page.PierceDOM(true, 10)
	if err != nil {
		t.Fatalf("PierceDOM: %v", err)
	}
	if len(snap.ClickListeners) != 10 || snap.ListenerNodesDropped != 20 {
		t.Fatalf("kept %d dropped %d, want 10/20", len(snap.ClickListeners), snap.ListenerNodesDropped)
	}

	cfg, _ := config.New(server.URL)
	cfg.MaxListenerProbeNodes = 10
	ext := NewCandidateElementExtractor(cfg)
	ext.SetClickSelectors([]string{"a"}) // listener pass only
	cands, err := ext.Extract(context.Background(), page)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(cands) != 10 {
		t.Fatalf("got %d candidates, want the 10 the cap allows", len(cands))
	}
}

// BenchmarkExtractPierced5k measures one state's candidate extraction on a
// ~5k-element DOM (rows of mixed elements, a web component every 25 rows, a
// click listener on every 10th row). Report: ms/op for the pierced snapshot
// alone and for the full Extract.
func BenchmarkExtractPierced5k(b *testing.B) {
	var sb strings.Builder
	sb.WriteString(`<!doctype html><html><body><script>
		customElements.define('x-w', class extends HTMLElement {
			connectedCallback() {
				const sr = this.attachShadow({mode: this.hasAttribute('closed') ? 'closed' : 'open'});
				sr.innerHTML = '<div><span>w</span><button>w</button></div>';
			}
		});
	</script>`)
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&sb, `<div class="row" id="r%d"><span>%d</span><p>t</p><i>x</i><em>y</em>`, i, i)
		if i%25 == 0 {
			if i%50 == 0 {
				sb.WriteString(`<x-w closed></x-w>`)
			} else {
				sb.WriteString(`<x-w></x-w>`)
			}
		}
		sb.WriteString(`</div>`)
	}
	sb.WriteString(`<script>document.querySelectorAll('.row').forEach((d, i) => { if (i % 10 === 0) d.addEventListener('click', () => {}); });</script></body></html>`)
	server, page := servePage(b, sb.String())

	if n, _ := page.Eval(`document.getElementsByTagName('*').length`); n == nil {
		b.Fatal("page not loaded")
	} else {
		b.Logf("light-DOM elements: %v", n)
	}

	b.Run("PierceDOM", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			snap, err := page.PierceDOM(true, 0)
			if err != nil {
				b.Fatal(err)
			}
			if len(snap.ClickListeners) != 100 {
				b.Fatalf("listeners = %d, want 100", len(snap.ClickListeners))
			}
		}
	})
	b.Run("Extract", func(b *testing.B) {
		cfg, _ := config.New(server.URL)
		ext := NewCandidateElementExtractor(cfg)
		ext.SetClickOnce(false) // every iteration extracts the same state afresh
		for i := 0; i < b.N; i++ {
			cands, err := ext.Extract(context.Background(), page)
			if err != nil {
				b.Fatal(err)
			}
			if len(cands) < 100 {
				b.Fatalf("only %d candidates", len(cands))
			}
		}
	})
}
