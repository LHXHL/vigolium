//go:build integration

package crawler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// shadowXHRPage is a web component rendering one button into an open shadow
// root and one into a closed shadow root. Each click handler fires an XHR whose
// URL is assembled at runtime (a literal would be found by static JS endpoint
// extraction and requested without any click). The closed-root button is
// reachable only through CDP pierce: no selector or script can see it.
const shadowXHRPage = `<!doctype html><html><body>
	<h1>shop</h1>
	<x-actions></x-actions>
	<x-vault></x-vault>
	<script>
		const api = (name) => ['', 'api', name].join('/');
		const send = (name) => () => {
			const x = new XMLHttpRequest();
			x.open('POST', api(name));
			x.send('{}');
		};
		customElements.define('x-actions', class extends HTMLElement {
			connectedCallback() {
				const sr = this.attachShadow({mode: 'open'});
				sr.innerHTML = '<div class="bar"><button type="button">Add to cart</button></div>';
				sr.querySelector('button').addEventListener('click', send('open' + '-cart'));
			}
		});
		customElements.define('x-vault', class extends HTMLElement {
			connectedCallback() {
				const sr = this.attachShadow({mode: 'closed'});
				sr.innerHTML = '<span>vault</span><button type="button">Unlock</button>';
				sr.querySelector('button').addEventListener('click', send('closed' + '-unlock'));
			}
		});
	</script>
</body></html>`

// TestCrawlFiresShadowRootXHRs: the crawler must find and click both
// web-component buttons — the open-root one through the selector pass's
// shadow walk, the closed-root one through the pierced CDP listener pass — and
// the network capture must record both XHRs.
func TestCrawlFiresShadowRootXHRs(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(shadowXHRPage))
	})
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	cfg, err := config.New(server.URL)
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	cfg.Headless = true
	cfg.MaxStates = 0
	cfg.MaxDepth = 0
	cfg.MaxDuration = 60 * time.Second

	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New crawler: %v", err)
	}
	rec := &recordingWriter{}
	c.SetWriter(rec)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if _, err := c.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if !rec.sawContaining("/api/open-cart") {
		t.Errorf("open-shadow-root button's XHR (/api/open-cart) was not captured")
	}
	if !rec.sawContaining("/api/closed-unlock") {
		t.Errorf("closed-shadow-root button's XHR (/api/closed-unlock) was not captured")
	}
}
