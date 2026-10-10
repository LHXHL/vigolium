//go:build integration

package browser

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// piercePage has a click-listener button in each place a candidate can hide:
// the light DOM, an open shadow root, an open root nested in another, a closed
// shadow root, and a same-origin frame hosted inside a shadow root. Every
// button records its name in window.__hits of the top document.
const piercePage = `<!doctype html><html><body>
	<div><button id="light">Light</button></div>
	<svg width="10" height="10"><rect width="10" height="10"></rect></svg>
	<x-open></x-open>
	<x-closed></x-closed>
	<script>
		window.__hits = [];
		const hit = (name) => () => { window.top.__hits.push(name); };
		document.getElementById('light').addEventListener('click', hit('light'));
		class XInner extends HTMLElement {
			connectedCallback() {
				const sr = this.attachShadow({mode: 'open'});
				sr.innerHTML = '<p>inner</p><button>Nested</button>';
				sr.querySelector('button').addEventListener('click', hit('nested'));
			}
		}
		class XOpen extends HTMLElement {
			connectedCallback() {
				const sr = this.attachShadow({mode: 'open'});
				sr.innerHTML = '<div><button>Open</button></div><x-inner></x-inner>' +
					'<iframe srcdoc="<body><button>Framed</button></body>"></iframe>';
				sr.querySelector('button').addEventListener('click', hit('open'));
				const f = sr.querySelector('iframe');
				f.addEventListener('load', () => {
					f.contentDocument.querySelector('button').addEventListener('click', hit('framed'));
					window.__frameReady = true;
				});
			}
		}
		class XClosed extends HTMLElement {
			connectedCallback() {
				const sr = this.attachShadow({mode: 'closed'});
				sr.innerHTML = '<span>closed</span><button>Closed</button>';
				sr.querySelector('button').addEventListener('click', hit('closed'));
			}
		}
		customElements.define('x-inner', XInner);
		customElements.define('x-open', XOpen);
		customElements.define('x-closed', XClosed);
	</script>
</body></html>`

func pierceServerPage(t *testing.T) *Page {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(piercePage))
	}))
	t.Cleanup(server.Close)
	cfg, err := config.New(server.URL)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	cfg.Headless = true
	b, err := New(cfg)
	if err != nil {
		t.Fatalf("browser: %v", err)
	}
	t.Cleanup(func() { b.Close() })
	p, err := b.NewPage()
	if err != nil {
		t.Fatalf("page: %v", err)
	}
	if err := p.Navigate(server.URL); err != nil {
		t.Fatalf("navigate: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ready, _ := p.Eval(`window.__frameReady === true`); ready == true {
			return p
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("shadow-hosted frame never loaded")
	return nil
}

func hits(t *testing.T, p *Page) []string {
	t.Helper()
	v, err := p.Eval(`window.__hits.slice()`)
	if err != nil {
		t.Fatalf("read hits: %v", err)
	}
	var out []string
	if arr, ok := v.([]interface{}); ok {
		for _, x := range arr {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	sort.Strings(out)
	return out
}

// TestPierceDOMListenerLocatorRoundTrip is the locator round trip against a
// real DOM: the pierced snapshot finds every click listener (closed root and
// shadow-hosted frame included), each snapshot locator matches what the live
// element reports for itself, and re-resolving the encoded locator through
// Page.Element — the path the crawler's click takes — reaches the element and
// fires its handler.
func TestPierceDOMListenerLocatorRoundTrip(t *testing.T) {
	p := pierceServerPage(t)

	snap, err := p.PierceDOM(true, 0)
	if err != nil {
		t.Fatalf("PierceDOM: %v", err)
	}
	if !snap.ListenersProbed {
		t.Fatal("listener probe did not run")
	}
	if len(snap.ClosedRoots) != 1 {
		t.Fatalf("closed roots = %d, want 1", len(snap.ClosedRoots))
	}

	byTagShadow := map[string]int{}
	for _, pe := range snap.ClickListeners {
		if pe.Tag != "button" {
			t.Errorf("unexpected listener element %s at %s", pe.Tag, pe.Locator)
			continue
		}
		live, err := p.ElementByBackendNodeID(pe.BackendNodeID)
		if err != nil {
			t.Fatalf("resolve %s by backend id: %v", pe.Locator, err)
		}
		self, err := live.Locator()
		if err != nil {
			t.Fatalf("Locator() for %s: %v", pe.Locator, err)
		}
		if self.String() != pe.Locator.String() {
			t.Errorf("snapshot locator %s != element's own %s", pe.Locator, self)
		}
		if pe.Locator.IsLight() {
			xp, _ := live.GetXPath()
			if xp != pe.Locator.InnerXPath {
				t.Errorf("snapshot XPath %s != GetXPath %s", pe.Locator.InnerXPath, xp)
			}
			byTagShadow["light"]++
		} else {
			byTagShadow["shadow"]++
		}

		// The crawler's click path: Page.Element(identification value).
		sel := pe.Locator.String()
		if pe.Locator.IsLight() {
			sel = pe.Locator.InnerXPath
			el, err := p.ElementX(sel)
			if err != nil {
				t.Fatalf("ElementX(%s): %v", sel, err)
			}
			if err := el.Click(); err != nil {
				t.Fatalf("click %s: %v", sel, err)
			}
			continue
		}
		el, err := p.Element(sel)
		if err != nil {
			t.Fatalf("Element(%s): %v", sel, err)
		}
		if err := el.Click(); err != nil {
			t.Fatalf("click %s: %v", sel, err)
		}
	}
	if byTagShadow["light"] != 1 || byTagShadow["shadow"] != 4 {
		t.Fatalf("listener elements light=%d shadow=%d, want 1/4", byTagShadow["light"], byTagShadow["shadow"])
	}
	time.Sleep(100 * time.Millisecond)
	got := strings.Join(hits(t, p), ",")
	if want := "closed,framed,light,nested,open"; got != want {
		t.Fatalf("clicks reached %q, want %q", got, want)
	}
}

// TestPiercingElementsFindsClosedAndFramed confirms the selector pass's query
// sees inside every boundary but returns no light-DOM match.
func TestPiercingElementsFindsClosedAndFramed(t *testing.T) {
	p := pierceServerPage(t)
	snap, err := p.PierceDOM(false, 0)
	if err != nil {
		t.Fatalf("PierceDOM: %v", err)
	}
	if snap.ListenersProbed {
		t.Fatal("listeners probed although not asked")
	}
	els, err := p.PiercingElements("button", snap)
	if err != nil {
		t.Fatalf("PiercingElements: %v", err)
	}
	var locs []string
	for _, e := range els {
		l, err := e.Locator()
		if err != nil {
			t.Fatalf("Locator: %v", err)
		}
		if l.IsLight() {
			t.Errorf("light-DOM match returned: %s", l)
		}
		locs = append(locs, l.String())
	}
	sort.Strings(locs)
	want := []string{
		`{"hostChain":["/html[1]/body[1]/x-closed[1]"],"innerXPath":"/button[1]"}`,
		`{"hostChain":["/html[1]/body[1]/x-open[1]","/iframe[1]"],"innerXPath":"/html[1]/body[1]/button[1]"}`,
		`{"hostChain":["/html[1]/body[1]/x-open[1]","/x-inner[1]"],"innerXPath":"/button[1]"}`,
		`{"hostChain":["/html[1]/body[1]/x-open[1]"],"innerXPath":"/div[1]/button[1]"}`,
	}
	if strings.Join(locs, "\n") != strings.Join(want, "\n") {
		t.Fatalf("locators:\n%s\nwant:\n%s", strings.Join(locs, "\n"), strings.Join(want, "\n"))
	}

	// Without the snapshot only the script-visible (open) boundaries are seen.
	open, err := p.PiercingElements("button", nil)
	if err != nil {
		t.Fatalf("PiercingElements(nil): %v", err)
	}
	if len(open) != 3 {
		t.Fatalf("open-only query found %d buttons, want 3", len(open))
	}
}

// TestElementByLocatorMissFailsFast confirms a locator that no longer matches
// errors out (after ElementTimeout) rather than resolving something else.
func TestElementByLocatorMiss(t *testing.T) {
	p := pierceServerPage(t)
	p.config.ElementTimeout = 300 * time.Millisecond
	_, err := p.Element(Locator{HostChain: []string{"/html[1]/body[1]/x-open[1]"}, InnerXPath: "/div[1]/button[2]"}.String())
	if err == nil {
		t.Fatal("expected a miss")
	}
}
