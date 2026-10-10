package http_request_smuggling

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// cl0Backend configures keepAliveHost, a raw TCP HTTP/1.1 server that serves
// any number of requests per connection. It is raw because the behaviour under
// test - a server that does not read a declared body - is exactly what
// net/http's server refuses to do.
type cl0Backend struct {
	// ignoreCL makes the server skip the declared body on static paths, leaving
	// it in the stream as the start of the next request (the CL.0 bug).
	ignoreCL bool
	// closeAfterEach answers every request with Connection: close and hangs up.
	closeAfterEach bool
	// all404 answers every path with 404.
	all404 bool
}

type keepAliveHost struct {
	addr string
	cfg  cl0Backend

	mu       sync.Mutex
	requests []string // request lines, in arrival order
}

func newKeepAliveHost(t *testing.T, cfg cl0Backend) *keepAliveHost {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	h := &keepAliveHost{addr: ln.Addr().String(), cfg: cfg}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go h.serve(conn)
		}
	}()
	return h
}

func (h *keepAliveHost) url(path string) string { return "http://" + h.addr + path }

func (h *keepAliveHost) requestLines() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.requests...)
}

func (h *keepAliveHost) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	br := bufio.NewReader(conn)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		var headers []string
		for {
			hl, err := br.ReadString('\n')
			if err != nil {
				return
			}
			hl = strings.TrimRight(hl, "\r\n")
			if hl == "" {
				break
			}
			headers = append(headers, hl)
		}
		h.mu.Lock()
		h.requests = append(h.requests, line)
		h.mu.Unlock()

		parts := strings.Fields(line)
		if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/") {
			_, _ = conn.Write([]byte(withBody("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n", "bad request")))
			return
		}
		bare, _, _ := strings.Cut(parts[1], "?")

		cl := 0
		for _, hl := range headers {
			if k, v, ok := strings.Cut(hl, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "Content-Length") {
				cl, _ = strconv.Atoi(strings.TrimSpace(v))
			}
		}
		static := bare == "/favicon.ico" || bare == "/robots.txt" || strings.HasSuffix(bare, ".css")
		skipBody := h.cfg.ignoreCL && static
		if cl > 0 && !skipBody {
			if _, err := io.CopyN(io.Discard, br, int64(cl)); err != nil {
				return
			}
		}

		status, body := "200 OK", "ok "+bare
		switch {
		case h.cfg.all404:
			status, body = "404 Not Found", "not found: "+bare
		case bare == "/favicon.ico", bare == "/robots.txt", bare == "/api/thing", bare == "/",
			strings.HasSuffix(bare, ".css"):
		default:
			status, body = "404 Not Found", "not found: "+bare
		}

		head := "HTTP/1.1 " + status + "\r\n"
		if h.cfg.closeAfterEach {
			head += "Connection: close\r\n"
		}
		if _, err := conn.Write([]byte(withBody(head, body))); err != nil {
			return
		}
		if h.cfg.closeAfterEach {
			return
		}
	}
}

func scanResults(t *testing.T, target string) []*output.ResultEvent {
	t.Helper()
	client := modtest.Requester(t)
	rr := modtest.Request(t, target)
	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	return results
}

func cl0Findings(results []*output.ResultEvent) []*output.ResultEvent {
	var out []*output.ResultEvent
	for _, r := range results {
		if r.Metadata["variant"] == "CL.0" {
			out = append(out, r)
		}
	}
	return out
}

// TestCL0_DetectsBackendIgnoringContentLength: a back-end that skips the body
// of a POST to /favicon.ico answers the follow-up GET with the smuggled
// canary's 404.
func TestCL0_DetectsBackendIgnoringContentLength(t *testing.T) {
	h := newKeepAliveHost(t, cl0Backend{ignoreCL: true})

	found := cl0Findings(scanResults(t, h.url("/api/thing")))
	require.Len(t, found, 1, "a CL-ignoring static handler is the CL.0 signature")

	f := found[0]
	assert.Equal(t, "HTTP Request Smuggling: CL.0 Desync", f.Info.Name)
	assert.Equal(t, severity.High, f.Info.Severity)
	assert.Equal(t, severity.Firm, f.Info.Confidence)
	assert.Equal(t, h.url("/favicon.ico"), f.URL)
	assert.Equal(t, 404, f.Metadata["followup_status"])
	assert.Equal(t, 200, f.Metadata["own_status"])
	assert.NotEqual(t, 404, f.Metadata["control_status"])
	assert.Equal(t, true, f.Metadata["canary_reflected"],
		"the fake 404 page echoes the path, so the canary must be visible in the follow-up")
	assert.Contains(t, f.Request, "POST /favicon.ico HTTP/1.1")
	assert.Contains(t, f.Request, "GET /vgcl0")
	assert.Contains(t, f.Response, "404")

	// The smuggled request must actually have been parsed by the server: its
	// request line arrives as a request of its own.
	var smuggled bool
	for _, l := range h.requestLines() {
		if strings.HasPrefix(l, "GET /vgcl0") && strings.Contains(l, " HTTP/1.1") {
			smuggled = true
		}
	}
	assert.True(t, smuggled, "the smuggled prefix never reached the server's parser")
}

// TestCL0_CapturedStaticPathIsACandidate: the captured request's own path is
// tried first when it looks static.
func TestCL0_CapturedStaticPathIsACandidate(t *testing.T) {
	h := newKeepAliveHost(t, cl0Backend{ignoreCL: true})

	found := cl0Findings(scanResults(t, h.url("/assets/site.css")))
	require.Len(t, found, 1)
	assert.Equal(t, h.url("/assets/site.css"), found[0].URL)
}

// TestCL0_NoFindingOnCorrectBackend: a server that honours Content-Length
// answers the follow-up with its own response.
func TestCL0_NoFindingOnCorrectBackend(t *testing.T) {
	h := newKeepAliveHost(t, cl0Backend{})
	assert.Empty(t, cl0Findings(scanResults(t, h.url("/api/thing"))))

	// The attack really went out: correct servers see the POSTs, and the
	// smuggled line stays inside a body, never parsed as a request.
	var posted bool
	for _, l := range h.requestLines() {
		if strings.HasPrefix(l, "POST /favicon.ico") {
			posted = true
		}
		assert.False(t, strings.HasPrefix(l, "GET /vgcl0") && strings.Contains(l, "X-Ignore"),
			"unexpected request line %q", l)
	}
	assert.True(t, posted, "no CL.0 attack pair was sent")
}

// TestCL0_NoFindingWhenServerClosesConnections: even a CL-ignoring server
// cannot be reported when it closes the connection after each response - there
// is no reused connection for the follow-up, so nothing was observed.
func TestCL0_NoFindingWhenServerClosesConnections(t *testing.T) {
	h := newKeepAliveHost(t, cl0Backend{ignoreCL: true, closeAfterEach: true})
	assert.Empty(t, cl0Findings(scanResults(t, h.url("/api/thing"))))
}

// TestCL0_NoFindingWhenOwnResponseIs404: when the follow-up's own answer is
// already a 404, "it got the canary's 404" is not a distinguishable event.
func TestCL0_NoFindingWhenOwnResponseIs404(t *testing.T) {
	h := newKeepAliveHost(t, cl0Backend{ignoreCL: true, all404: true})
	assert.Empty(t, cl0Findings(scanResults(t, h.url("/api/thing"))))
}

func TestCL0Candidates(t *testing.T) {
	tests := []struct {
		target string
		want   []string
	}{
		{"http://example.com/api/thing", []string{"/favicon.ico", "/robots.txt"}},
		{"http://example.com/static/app.js?v=1", []string{"/static/app.js?v=1", "/favicon.ico", "/robots.txt"}},
		{"http://example.com/favicon.ico", []string{"/favicon.ico", "/robots.txt"}},
	}
	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			rr := modtest.Request(t, tt.target)
			assert.Equal(t, tt.want, cl0Candidates(rr))
		})
	}
}

func TestBuildCL0Request_DeclaresTrueLengthAndKeepsAlive(t *testing.T) {
	rr := modtest.Request(t, "http://example.com/api/thing")
	body := cl0SmuggledPrefix("/vgcl0abc")
	raw, ok := buildCL0Request(rr, "POST", "/favicon.ico", body)
	require.True(t, ok)
	s := string(raw)

	assert.True(t, strings.HasPrefix(s, "POST /favicon.ico HTTP/1.1\r\n"))
	assert.Contains(t, s, fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	assert.Contains(t, s, "Connection: keep-alive\r\n")
	assert.NotContains(t, strings.ToLower(s), "transfer-encoding")
	assert.True(t, strings.HasSuffix(s, "\r\n\r\n"+body), "the smuggled prefix must be the exact body")
	assert.Equal(t, 1, strings.Count(strings.ToLower(s), "\r\nconnection:"))
}
