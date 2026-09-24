package provider

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/http2"

	"github.com/vigolium/vigolium/pkg/olium/stream"
)

// ConnectionResetter is the optional interface providers implement so the
// engine can drop idle conns on the failing provider between retry
// attempts — useful when an upstream proxy poisons a specific TCP+TLS
// conn (RST_STREAM after RST_STREAM) and a fresh handshake is the only
// escape. Providers without HTTP state can leave this unimplemented.
type ConnectionResetter interface {
	CloseIdleConnections()
}

// drainAndClose discards a response body we are not going to read and closes
// it. Draining first is what lets the transport reuse the connection for the
// retry that follows — closing an unread body abandons the TCP conn, so the
// second request pays a fresh handshake.
func drainAndClose(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, body)
	_ = body.Close()
}

// newHTTPClient returns an *http.Client whose HTTP/2 transport sends
// keepalive PING frames on idle connections. Bare http.DefaultTransport
// gets HTTP/2 auto-upgrade but leaves ReadIdleTimeout=0, so a stale conn
// surfaces as `stream error: stream ID N; INTERNAL_ERROR; received from
// peer` on the next request instead of being detected up front.
func newHTTPClient() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	if h2, err := http2.ConfigureTransports(t); err == nil && h2 != nil {
		h2.ReadIdleTimeout = 30 * time.Second
		h2.PingTimeout = 15 * time.Second
	}
	return &http.Client{Transport: t}
}

// maxErrorBodyBytes bounds how much of a non-200 response body is read. The
// body is diagnostic text destined for an error message; a proxy that
// answers an error with megabytes of HTML should not be buffered whole.
const maxErrorBodyBytes = 64 << 10

// readErrorBody reads at most maxErrorBodyBytes from an error response, then
// drains and closes it so the transport can reuse the connection for the
// retry that usually follows (see drainAndClose).
func readErrorBody(body io.ReadCloser) []byte {
	raw, _ := io.ReadAll(io.LimitReader(body, maxErrorBodyBytes))
	drainAndClose(body)
	return raw
}

// statusErrorFrom builds the typed error for a non-200 response: bounded
// read, drain, close, and the vendor's own message where it has one. One
// helper so no driver can get half of that right.
func statusErrorFrom(label string, resp *http.Response) *stream.StatusError {
	return stream.NewStatusError(label, resp.StatusCode, []byte(providerErrorMessage(readErrorBody(resp.Body))))
}

// providerErrorMessage digs the human-readable message out of an error body.
// OpenAI-compatible servers disagree on the shape: OpenAI nests it under
// "error", vLLM returns {"object":"error","message":...}, FastAPI gateways
// return {"detail":...}, and Ollama returns {"error":"..."} as a bare
// string. Falling back to the raw body keeps anything unrecognized visible.
func providerErrorMessage(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var shaped struct {
		Error struct {
			Code     string  `json:"code"`
			Type     string  `json:"type"`
			Message  string  `json:"message"`
			PlanType string  `json:"plan_type"`
			ResetsAt float64 `json:"resets_at"`
		} `json:"error"`
		Message string `json:"message"` // vLLM
		Detail  string `json:"detail"`  // FastAPI
	}
	if err := json.Unmarshal(raw, &shaped); err == nil {
		for _, candidate := range []string{shaped.Error.Message, shaped.Message, shaped.Detail} {
			if candidate != "" {
				return candidate
			}
		}
	}
	// Ollama: {"error": "some text"} - error is a string, not an object.
	var bare struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &bare); err == nil && bare.Error != "" {
		return bare.Error
	}
	return strings.TrimSpace(string(raw))
}
