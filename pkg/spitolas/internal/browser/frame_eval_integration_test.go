//go:build integration

package browser

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestFrameEvalRunsInFrameDocument pins that the raw Runtime.evaluate paths
// (Eval, EvalCDP and the getEventListeners helpers) run in a frame page's own
// document, nested frames included. A frame page shares its tab's CDP session,
// so without an explicit context they evaluated the top document, and the CDP
// clickable pass resolved the parent's XPaths inside the frame instead.
func TestFrameEvalRunsInFrameDocument(t *testing.T) {
	mux := http.NewServeMux()
	page := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<!doctype html><html><body>" + body + "</body></html>"))
		}
	}
	mux.HandleFunc("/", page(`<iframe id="outer" src="/outer"></iframe>`))
	mux.HandleFunc("/outer", page(`<iframe id="inner" src="/inner"></iframe>`))
	mux.HandleFunc("/inner", page(`<a id="go" href="#">go</a>
		<script>document.getElementById('go').addEventListener('click', function () {});</script>`))
	server := httptest.NewServer(mux)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	p, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}
	if err := p.Navigate(server.URL + "/"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	outer := onlyFrame(t, p, "outer")
	inner := onlyFrame(t, outer, "inner")

	for _, tc := range []struct {
		name string
		page *Page
		want string
	}{
		{"top", p, "/"},
		{"outer", outer, "/outer"},
		{"inner", inner, "/inner"},
	} {
		for evalName, eval := range map[string]func(string) (interface{}, error){
			"Eval": tc.page.Eval, "EvalCDP": tc.page.EvalCDP,
		} {
			got, err := eval("location.pathname")
			if err != nil {
				t.Fatalf("%s %s: %v", tc.name, evalName, err)
			}
			if got != tc.want {
				t.Errorf("%s %s(location.pathname) = %v, want %s", tc.name, evalName, got, tc.want)
			}
		}
	}

	// The Command Line API is available in the frame's context, so its own
	// listener is visible there.
	listeners, err := inner.GetEventListeners("#go")
	if err != nil {
		t.Fatalf("inner GetEventListeners: %v", err)
	}
	if _, ok := listeners["click"]; !ok {
		t.Errorf("inner GetEventListeners(#go) = %v, want a click listener", listeners)
	}
}

func onlyFrame(t *testing.T, p *Page, id string) *Page {
	t.Helper()
	frames, err := p.FramesWithInfo()
	if err != nil {
		t.Fatalf("FramesWithInfo() failed: %v", err)
	}
	for _, f := range frames {
		if f.ID == id {
			return f.Page
		}
	}
	t.Fatalf("frame %q not found among %d frames", id, len(frames))
	return nil
}
