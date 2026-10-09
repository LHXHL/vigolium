//go:build integration

package crawler

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/network"
)

// entryWriter keeps every captured entry.
type entryWriter struct {
	mu      sync.Mutex
	entries []*network.TrafficEntry
}

func (w *entryWriter) Write(e *network.TrafficEntry) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.entries = append(w.entries, e)
	return nil
}

func (w *entryWriter) Close() error { return nil }

func (w *entryWriter) find(method, path string) *network.TrafficEntry {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, e := range w.entries {
		if e.Request.Method == method && strings.Contains(e.Request.URL, path) {
			return e
		}
	}
	return nil
}

// TestCaptureRecordsCookieAndLargePostBody drives a real browser: the landing
// page sets a cookie, then posts a ~200 KB multipart form with a file part.
// Chrome adds the Cookie header only on the wire (requestWillBeSentExtraInfo)
// and leaves a blob-backed body out of requestWillBeSent, so the record has both
// only when the capture merges ExtraInfo and fetches the body with
// getRequestPostData. (A plain 200 KB string field is sent inline and would not
// exercise the fetch.)
func TestCaptureRecordsCookieAndLargePostBody(t *testing.T) {
	var received atomic.Int64
	uploaded := make(chan struct{}, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "e3-cookie", Path: "/"})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><html><body><p>upload</p><script>
			const fd = new FormData();
			fd.append('note', 'hello');
			fd.append('payload', new Blob(['P'.repeat(200 * 1024)], {type: 'text/plain'}), 'payload.txt');
			fetch('/upload', {method: 'POST', body: fd, credentials: 'same-origin'});
		</script></body></html>`))
	})
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received.Store(int64(len(body)))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
		select {
		case uploaded <- struct{}{}:
		default:
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	cfg, err := config.New(server.URL)
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	cfg.Headless = true
	cfg.MaxStates = 1
	cfg.MaxDepth = 0
	cfg.MaxDuration = 30 * time.Second

	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New crawler: %v", err)
	}
	w := &entryWriter{}
	c.SetWriter(w)
	var sent, inScope atomic.Int64
	c.AddRequestCounters(network.RequestCounters{Sent: &sent, InScope: &inScope})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := c.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}
	select {
	case <-uploaded:
	default:
		t.Fatal("the page never posted to /upload")
	}

	e := w.find("POST", "/upload")
	if e == nil {
		t.Fatal("no captured record for POST /upload")
	}
	var cookie string
	for k, v := range e.Request.Headers {
		if strings.EqualFold(k, "Cookie") {
			cookie = v
		}
	}
	if !strings.Contains(cookie, "sid=e3-cookie") {
		t.Errorf("Cookie header = %q, want it to carry sid=e3-cookie (headers %v)", cookie, e.Request.Headers)
	}
	if got, want := int64(len(e.Request.Body)), received.Load(); got != want || want < 200*1024 {
		t.Errorf("captured body = %d bytes, server received %d", got, want)
	}
	if !strings.Contains(string(e.Request.Body), `name="payload"`) {
		t.Errorf("captured body is not the multipart form")
	}
	if sent.Load() < 2 || inScope.Load() < 2 || inScope.Load() > sent.Load() {
		t.Errorf("request counters sent=%d inScope=%d, want >= 2 each and inScope <= sent", sent.Load(), inScope.Load())
	}
}
