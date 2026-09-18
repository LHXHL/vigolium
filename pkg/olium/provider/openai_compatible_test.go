package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/olium/stream"
)

// TestOpenAICompatible_RoutingAndHeaders verifies the three behaviors that
// distinguish openai-compatible from the canonical OpenAI provider:
//   - the request is sent to the configured base_url, not api.openai.com
//   - the Authorization header is suppressed when the api_key is empty
//     (so unauthenticated local servers like Ollama work)
//   - extra_headers are applied and can override standard headers
//
// The fake server replies with a single content delta + [DONE] so the SSE
// reader has just enough to produce text_start / text_delta / text_end / done.
func TestOpenAICompatible_RoutingAndHeaders(t *testing.T) {
	type capture struct {
		method     string
		path       string
		authHeader string
		extra      string
		ctype      string
		accept     string
	}

	cases := []struct {
		name         string
		baseURLPath  string // appended to httptest server URL — covers normalization
		apiKey       string
		extraHeaders map[string]string
		wantAuth     string // value expected in Authorization; "" means header must be absent
		wantExtra    string // value expected in X-Test header
	}{
		{
			name:        "ollama_style_no_key_v1_root",
			baseURLPath: "/v1",
			apiKey:      "",
			wantAuth:    "",
		},
		{
			name:        "openrouter_style_with_key_full_url",
			baseURLPath: "/v1/chat/completions",
			apiKey:      "or-test-key",
			wantAuth:    "Bearer or-test-key",
		},
		{
			name:         "extra_headers_applied_and_can_override_auth",
			baseURLPath:  "/v1",
			apiKey:       "ignored-by-override",
			extraHeaders: map[string]string{"Authorization": "Api-Key custom-scheme", "X-Test": "hello"},
			wantAuth:     "Api-Key custom-scheme",
			wantExtra:    "hello",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got capture
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got.method = r.Method
				got.path = r.URL.Path
				got.authHeader = r.Header.Get("Authorization")
				got.extra = r.Header.Get("X-Test")
				got.ctype = r.Header.Get("Content-Type")
				got.accept = r.Header.Get("Accept")

				writeOpenAISSEStub(w)
			}))
			defer srv.Close()

			p := NewOpenAICompatible(srv.URL+tc.baseURLPath, tc.apiKey, tc.extraHeaders, nil)

			events, err := p.Stream(context.Background(), Request{
				Model:    "test-model",
				System:   "you are a test",
				Messages: []Message{{Role: RoleUser, Text: "ping"}},
			})
			if err != nil {
				t.Fatalf("Stream: %v", err)
			}
			// Drain to ensure the reader doesn't error out on our fake stream.
			var sawDone bool
			for ev := range events {
				if ev.Type == stream.EventDone {
					sawDone = true
				}
				if ev.Type == stream.EventError {
					t.Fatalf("stream error: %s", ev.Err)
				}
			}
			if !sawDone {
				t.Fatalf("expected EventDone, got none")
			}

			if got.method != http.MethodPost {
				t.Errorf("method = %q, want POST", got.method)
			}
			if !strings.HasSuffix(got.path, "/chat/completions") {
				t.Errorf("path = %q, expected to end in /chat/completions", got.path)
			}
			if got.authHeader != tc.wantAuth {
				t.Errorf("Authorization = %q, want %q", got.authHeader, tc.wantAuth)
			}
			if tc.wantExtra != "" && got.extra != tc.wantExtra {
				t.Errorf("X-Test header = %q, want %q", got.extra, tc.wantExtra)
			}
			if got.ctype != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", got.ctype)
			}
			if got.accept != "text/event-stream" {
				t.Errorf("Accept = %q, want text/event-stream", got.accept)
			}
			if p.Name() != "openai-compatible" {
				t.Errorf("Name() = %q, want openai-compatible", p.Name())
			}
		})
	}
}

// TestNormalizeOpenAIBaseURL covers the URL handling we promise users — a
// /v1 root and a full /v1/chat/completions URL should both work, and
// trailing slashes shouldn't produce double-slash paths.
func TestNormalizeOpenAIBaseURL(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"http://localhost:11434/v1", "http://localhost:11434/v1/chat/completions"},
		{"http://localhost:11434/v1/", "http://localhost:11434/v1/chat/completions"},
		{"http://localhost:11434/v1/chat/completions", "http://localhost:11434/v1/chat/completions"},
		{"http://localhost:11434/v1/chat/completions/", "http://localhost:11434/v1/chat/completions"},
		{"  https://openrouter.ai/api/v1  ", "https://openrouter.ai/api/v1/chat/completions"},
		// A bare host gets /v1 too. Written without it, the same local server
		// that answers on /v1 used to get a POST to its root and 404.
		{"http://127.0.0.1:8317", "http://127.0.0.1:8317/v1/chat/completions"},
		{"http://127.0.0.1:8317/", "http://127.0.0.1:8317/v1/chat/completions"},
		{"", ""},
	}
	for _, c := range cases {
		if got := normalizeOpenAIBaseURL(c.in); got != c.want {
			t.Errorf("normalizeOpenAIBaseURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestAltOpenAIBaseURL pins the toggle that makes the /v1 guess recoverable:
// each spelling must produce the other, and a URL that isn't a
// chat-completions endpoint has no alternate worth trying.
func TestAltOpenAIBaseURL(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"http://h:1/v1/chat/completions", "http://h:1/chat/completions"},
		{"http://h:1/chat/completions", "http://h:1/v1/chat/completions"},
		{"https://openrouter.ai/api/v1/chat/completions", "https://openrouter.ai/api/chat/completions"},
		{"http://h:1/v1", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := altOpenAIBaseURL(c.in); got != c.want {
			t.Errorf("altOpenAIBaseURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestOpenAICompatible_V1Fallback covers the recovery path in both
// directions: a server that mounts the API at its root (so the /v1 we added
// 404s) and one that mounts it under /v1 when the operator's URL said
// otherwise. Either way the turn succeeds, and the working spelling is
// latched so the probe is not repeated every turn.
func TestOpenAICompatible_V1Fallback(t *testing.T) {
	cases := []struct {
		name      string
		servePath string // the only path the fake server answers
		baseURL   string // path appended to the server URL, as configured
	}{
		{"server_at_root_config_bare_host", "/chat/completions", ""},
		{"server_under_v1_config_omitted_it", "/v1/chat/completions", "/chat/completions"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seen pathRecorder
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen.add(r.URL.Path)
				if r.URL.Path != tc.servePath {
					http.NotFound(w, r)
					return
				}
				writeOpenAISSEStub(w)
			}))
			defer srv.Close()

			p := NewOpenAICompatible(srv.URL+tc.baseURL, "", nil, nil)

			drainStream(t, p)
			paths := seen.snapshot()
			if len(paths) != 2 {
				t.Fatalf("first turn sent %d requests (%v), want 2 (the guess, then the fallback)", len(paths), paths)
			}
			if paths[1] != tc.servePath {
				t.Errorf("fallback went to %q, want %q", paths[1], tc.servePath)
			}

			// The winner is remembered: a second turn costs one request.
			drainStream(t, p)
			if paths := seen.snapshot(); len(paths) != 3 {
				t.Errorf("second turn sent %d requests total (%v), want 3 — the working URL was not latched", len(paths), paths)
			}
		})
	}
}

// pathRecorder collects the paths a fake server was asked for. The handler
// runs on the server's own goroutine, so the slice needs a lock to stay clean
// under -race.
type pathRecorder struct {
	mu    sync.Mutex
	paths []string
}

func (p *pathRecorder) add(path string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.paths = append(p.paths, path)
}

func (p *pathRecorder) snapshot() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.paths...)
}

// writeOpenAISSEStub writes the minimal valid OpenAI SSE stream — one content
// delta then [DONE] — which is all the reader needs to produce
// text_start / text_delta / text_end / done.
func writeOpenAISSEStub(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, "data: %s\n\n", `{"choices":[{"delta":{"content":"hi"}}]}`)
	_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
}

// drainStream runs one turn and consumes it, failing the test on any error.
func drainStream(t *testing.T, p *OpenAI) {
	t.Helper()
	events, err := p.Stream(context.Background(), Request{
		Model:    "test-model",
		Messages: []Message{{Role: RoleUser, Text: "ping"}},
	})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	for ev := range events {
		if ev.Type == stream.EventError {
			t.Fatalf("stream error: %s", ev.Err)
		}
	}
}

// A 404 from BOTH spellings is a real missing endpoint, not a /v1 mixup. The
// error has to say so — and the second turn must not pay for the probe again.
func TestOpenAICompatible_V1FallbackBothFail(t *testing.T) {
	var seen pathRecorder
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.add(r.URL.Path)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	p := NewOpenAICompatible(srv.URL, "", nil, nil)
	req := Request{Model: "test-model", Messages: []Message{{Role: RoleUser, Text: "ping"}}}

	_, err := p.Stream(context.Background(), req)
	if err == nil {
		t.Fatal("Stream succeeded against a server that 404s everything")
	}
	if !strings.Contains(err.Error(), "also tried") {
		t.Errorf("error = %q, want it to name the alternate that was tried", err)
	}
	if hits := len(seen.snapshot()); hits != 2 {
		t.Fatalf("first turn sent %d requests, want 2", hits)
	}

	if _, err := p.Stream(context.Background(), req); err == nil {
		t.Fatal("second Stream succeeded unexpectedly")
	}
	if hits := len(seen.snapshot()); hits != 3 {
		t.Errorf("total requests = %d, want 3 — the exhausted alternate was retried", hits)
	}
}
