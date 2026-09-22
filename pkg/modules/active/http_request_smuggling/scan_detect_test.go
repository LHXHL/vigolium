package http_request_smuggling

import (
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// shrinkThresholds scales the timing gates down so an end-to-end test can run in
// milliseconds instead of tens of seconds. The RATIOS under test are unchanged;
// only the absolute floor and margin move.
func shrinkThresholds(t *testing.T) {
	t.Helper()
	oldFloor, oldMargin := timingFloor, probeControlMargin
	timingFloor = 100 * time.Millisecond
	probeControlMargin = 80 * time.Millisecond
	t.Cleanup(func() {
		timingFloor, probeControlMargin = oldFloor, oldMargin
	})
}

// wireRequest is one request as the fake host received it, parsed just enough to
// decide how to answer.
type wireRequest struct {
	method  string
	headers []string
}

func (w wireRequest) header(name string) []string {
	var out []string
	for _, line := range w.headers {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), name) {
			out = append(out, strings.TrimSpace(v))
		}
	}
	return out
}

// hasConflictingFraming reports whether this request carries both a
// Content-Length and a Transfer-Encoding, i.e. whether it is actually a
// smuggling probe as opposed to a well-formed POST. A fake origin can only
// behave differently for a probe if the probe's framing survived to the wire,
// so every desync scenario below doubles as proof that it did.
func (w wireRequest) hasConflictingFraming() bool {
	return len(w.header("Content-Length")) > 0 && len(w.header("Transfer-Encoding")) > 0
}

// fakeHost is a raw TCP HTTP/1.1 server. It is raw rather than httptest because
// the probes are deliberately malformed: net/http's server would reject a
// request carrying both Content-Length and Transfer-Encoding before any handler
// ran, so the scenarios under test could never be expressed.
type fakeHost struct {
	addr   string
	answer func(w wireRequest) (delay time.Duration, response string)

	mu   sync.Mutex
	seen []string
}

func newFakeHost(t *testing.T, answer func(w wireRequest) (time.Duration, string)) *fakeHost {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	h := &fakeHost{addr: ln.Addr().String(), answer: answer}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

				buf := make([]byte, 8192)
				n, _ := conn.Read(buf)
				if n == 0 {
					return
				}
				raw := string(buf[:n])
				head, _, _ := strings.Cut(raw, "\r\n\r\n")
				lines := strings.Split(head, "\r\n")
				w := wireRequest{}
				if len(lines) > 0 {
					w.method, _, _ = strings.Cut(lines[0], " ")
					w.headers = lines[1:]
				}
				h.record(raw)

				delay, response := h.answer(w)
				if response == "" {
					return // hang up without answering
				}
				time.Sleep(delay)
				_, _ = conn.Write([]byte(response))
			}(conn)
		}
	}()
	return h
}

func (h *fakeHost) url() string { return "http://" + h.addr + "/api/thing" }

// record is called from a per-connection goroutine, so the slice needs a lock
// even though the module's own sends are sequential.
func (h *fakeHost) record(raw string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seen = append(h.seen, raw)
}

func (h *fakeHost) wire() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.seen)
}

func (h *fakeHost) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.seen)
}

// withBody completes a response: the caller supplies the status line and any
// headers (each CRLF-terminated), and this adds the Content-Length and body.
func withBody(head, body string) string {
	return fmt.Sprintf("%sContent-Length: %d\r\n\r\n%s", head, len(body), body)
}

func okResponse(body string) string {
	return fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(body), body)
}

func scan(t *testing.T, h *fakeHost) []string {
	t.Helper()
	client := modtest.Requester(t)
	rr := modtest.Request(t, h.url())
	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	names := make([]string, 0, len(results))
	for _, r := range results {
		names = append(names, r.Info.Name)
	}
	return names
}

// TestScanPerHost_SlowPostHostProducesNoFindings reproduces the engagement false
// positive end to end. The host is simply slow for POST traffic: the probe, the
// control and everything else take the same long time, while a GET is fast.
//
// The old module compared the probe against that fast GET baseline and called
// the equally-slow control "fast", reporting a desync on every probe. Nothing
// here may be reported.
func TestScanPerHost_SlowPostHostProducesNoFindings(t *testing.T) {
	shrinkThresholds(t)

	h := newFakeHost(t, func(w wireRequest) (time.Duration, string) {
		if w.method == "GET" {
			// The CDN-cached GET the old baseline was taken from.
			return 0, okResponse(`{"ok":true}`)
		}
		// Every POST is slow, malformed or not. This is the whole scenario.
		return 220 * time.Millisecond, okResponse(`{"ok":true}`)
	})

	findings := scan(t, h)
	assert.Empty(t, findings,
		"a host that is uniformly slow for POST must produce no smuggling findings; "+
			"got %v", findings)
}

// TestScanPerHost_GenuineDesyncIsDetected is the other half: a host where ONLY
// the conflicting-framing request stalls, exactly as a back-end left waiting for
// chunk bytes would. This must still be caught, so the false-positive fixes did
// not simply disable the module.
func TestScanPerHost_GenuineDesyncIsDetected(t *testing.T) {
	shrinkThresholds(t)

	h := newFakeHost(t, func(w wireRequest) (time.Duration, string) {
		if w.hasConflictingFraming() {
			// The back-end is blocked waiting for a chunk that never comes.
			return 220 * time.Millisecond, okResponse(`{"ok":true}`)
		}
		return 0, okResponse(`{"ok":true}`)
	})

	findings := scan(t, h)
	assert.NotEmpty(t, findings,
		"a stall specific to conflicting CL/TE framing is the signature this module exists to find")
}

// TestScanPerHost_ProbesReachTheWireWithConflictingFraming asserts the bytes the
// fake origin actually received. This is the regression test for the deepest
// bug: probes used to be sent through net/http, which derives framing from
// req.ContentLength and req.TransferEncoding and ignores the headers — so
// Transfer-Encoding was dropped and Content-Length was rewritten to the true
// body length. Every "smuggling probe" arrived as an ordinary well-formed POST,
// byte-identical in framing to the control it was compared against.
func TestScanPerHost_ProbesReachTheWireWithConflictingFraming(t *testing.T) {
	shrinkThresholds(t)

	h := newFakeHost(t, func(w wireRequest) (time.Duration, string) {
		return 0, okResponse(`{"ok":true}`)
	})
	_ = scan(t, h)

	var sawConflict, sawDeclaredCL, sawDuplicateTE bool
	for _, raw := range h.wire() {
		head, _, _ := strings.Cut(raw, "\r\n\r\n")
		lines := strings.Split(head, "\r\n")
		w := wireRequest{headers: lines[1:]}
		if w.hasConflictingFraming() {
			sawConflict = true
		}
		// The CL.TE probe declares 4 while sending an 11-byte body. If anything
		// recomputed it, this never appears.
		for _, cl := range w.header("Content-Length") {
			if cl == "4" || cl == "6" {
				sawDeclaredCL = true
			}
		}
		if len(w.header("Transfer-Encoding")) == 2 {
			sawDuplicateTE = true
		}
	}

	assert.True(t, sawConflict,
		"no probe reached the origin carrying both Content-Length and Transfer-Encoding; "+
			"the framing was normalized away and nothing was actually tested")
	assert.True(t, sawDeclaredCL,
		"the probes' declared Content-Length (4 / 6) never reached the wire, so the "+
			"CL/TE disagreement that IS the attack was repaired in transit")
	assert.True(t, sawDuplicateTE,
		"the TE.TE probe must arrive with two Transfer-Encoding headers")
}

// TestScanPerHost_SkipsUntestableHost covers the preconditions that make a
// timing reading meaningless before a single probe is sent. Each host here must
// be abandoned after the one precondition request, never probed.
func TestScanPerHost_SkipsUntestableHost(t *testing.T) {
	akamai := `<html><head><title>Access Denied</title></head><body>` +
		`Access Denied - server: AkamaiGHost</body></html>`

	tests := []struct {
		name     string
		response string
		why      string
	}{
		{
			name:     "closes the connection",
			response: withBody("HTTP/1.1 200 OK\r\nConnection: close\r\n", `{"ok":true}`),
			why: "smuggling needs a connection the next request reuses; a host that " +
				"closes every one leaves no socket to poison",
		},
		{
			name:     "edge answers everything",
			response: withBody("HTTP/1.1 403 Forbidden\r\nServer: AkamaiGHost\r\n", akamai),
			why:      "no request reaches an origin parser chain, so no reading can be attributed",
		},
		{
			name: "auth gate answers everything",
			response: withBody("HTTP/1.1 401 Unauthorized\r\n"+
				"WWW-Authenticate: Bearer error=\"invalid_request\"\r\n", `{"error":"invalid_request"}`),
			why: "the request is rejected on credentials before the application processes it",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shrinkThresholds(t)
			h := newFakeHost(t, func(w wireRequest) (time.Duration, string) {
				return 0, tt.response
			})

			assert.Empty(t, scan(t, h), tt.why)
			assert.LessOrEqual(t, h.count(), 1,
				"must be skipped after the precondition request, not probed: %s", tt.why)
		})
	}
}

// TestScanPerHost_SkipsWhenControlIsBlocked covers the gap that let a fast edge
// 403 on the control read as "fast, therefore the probe's slowness is
// desync-specific". The control's response was never checked at all.
func TestScanPerHost_SkipsWhenControlIsBlocked(t *testing.T) {
	shrinkThresholds(t)

	block := `<html>Access Denied - AkamaiGHost</html>`
	h := newFakeHost(t, func(w wireRequest) (time.Duration, string) {
		switch {
		case w.method == "GET":
			return 0, okResponse(`{"ok":true}`)
		case w.hasConflictingFraming():
			// A probe that looks like a textbook desync...
			return 220 * time.Millisecond, okResponse(`{"ok":true}`)
		default:
			// ...but the control never reaches the origin, so there is no
			// reference reading and nothing may be concluded.
			return 0, fmt.Sprintf(
				"HTTP/1.1 403 Forbidden\r\nContent-Length: %d\r\n\r\n%s", len(block), block)
		}
	})

	findings := scan(t, h)
	assert.Empty(t, findings,
		"a blocked control is not a fast control; with no valid reference the probe "+
			"must not be reported, got %v", findings)
}
