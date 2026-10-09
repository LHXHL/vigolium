// Package h2race sends hand-framed HTTP requests that the shared Requester
// cannot express: several requests released in one TCP write (the
// single-packet race technique), and HTTP/2 requests whose header block
// carries framing headers Go's http2 client refuses to emit (a content-length
// that disagrees with the DATA frames, a transfer-encoding header).
//
// Two transports cover the two cases:
//
//   - SinglePacket opens ONE TLS connection with ALPN h2, sends every
//     request's HEADERS (and all but the last body byte) with END_STREAM
//     withheld, then releases the final DATA frame of every stream in a single
//     write. A server that only acts once a request body is complete receives
//     all N completions inside one packet.
//   - LastByteSync is the HTTP/1.1 fallback: N pre-opened connections each get
//     their request minus its final byte, then the final bytes go out in a
//     tight loop.
//
// Both write raw frames/bytes over a connection this package dials itself,
// so they bypass the scan's rate limiter, custom headers and carried sessions,
// like the CL.0 probe in http_request_smuggling. Egress honours an HTTP
// CONNECT proxy given in Options.ProxyURL; any other proxy scheme is refused
// (ErrUnsupportedProxy) rather than silently bypassed. Callers that cannot see
// the scan's --proxy value may use EnvProxyURL, which mirrors the environment
// fallback of the shared Requester.
package h2race

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Errors returned by the transports. Connection-level failures are returned
// from the call; per-request failures land in Response.Err.
var (
	// ErrNotH2 means the server did not negotiate h2 over ALPN (or the target
	// is not TLS). Callers fall back to LastByteSync.
	ErrNotH2 = errors.New("h2race: server did not negotiate HTTP/2")
	// ErrTooManyStreams means the batch exceeds the server's
	// SETTINGS_MAX_CONCURRENT_STREAMS.
	ErrTooManyStreams = errors.New("h2race: batch exceeds the server's concurrent stream limit")
	// ErrBodyTooLarge means the bodies do not fit in the peer's initial flow
	// control windows, so the frames could not all be written up front.
	ErrBodyTooLarge = errors.New("h2race: request bodies exceed the peer's flow-control window")
	// ErrUnsupportedProxy means a proxy is configured whose scheme is not a
	// plain HTTP CONNECT proxy.
	ErrUnsupportedProxy = errors.New("h2race: only http:// CONNECT proxies are supported")
	// ErrTimeout marks a request that got no complete response before the
	// exchange deadline.
	ErrTimeout = errors.New("h2race: no response before the deadline")
	// ErrStreamReset marks an HTTP/2 stream the server reset (RST_STREAM).
	ErrStreamReset = errors.New("h2race: stream reset by server")
	// ErrRefused marks a stream the server never processed (GOAWAY below its
	// id, or a connection that died before the response).
	ErrRefused = errors.New("h2race: stream not processed by server")
	// ErrEmptyRequest marks a request with no bytes to withhold.
	ErrEmptyRequest = errors.New("h2race: empty request")
)

const (
	defaultTimeout = 10 * time.Second
	defaultMaxBody = 1 << 20
)

// Target is the origin a batch is sent to.
type Target struct {
	Host string
	Port int
	TLS  bool
	// ServerName is the TLS SNI. Empty means Host (left unset for IP literals).
	ServerName string
}

func (t Target) addr() string { return net.JoinHostPort(t.Host, strconv.Itoa(t.Port)) }

// Header is one header field, sent verbatim and in order. Duplicates are
// allowed: the smuggling probes depend on it.
type Header struct {
	Name  string
	Value string
}

// Request is a transport-neutral request. Over HTTP/2, Method, Scheme,
// Authority and Path become pseudo-headers and Header names are lowercased;
// nothing else is validated or added, so a content-length that disagrees with
// Body is sent as given. Over HTTP/1.1 (WireH1) the request line, Host and a
// Content-Length (only when the caller set none) are added.
type Request struct {
	Method    string
	Scheme    string
	Authority string
	Path      string
	Header    []Header
	Body      []byte
}

// hasHeader reports whether r carries a header named name (case-insensitive).
func (r Request) hasHeader(name string) bool {
	for _, h := range r.Header {
		if strings.EqualFold(h.Name, name) {
			return true
		}
	}
	return false
}

// WireH1 renders r as an HTTP/1.1 request.
func (r Request) WireH1() []byte {
	var b strings.Builder
	path := r.Path
	if path == "" {
		path = "/"
	}
	b.WriteString(r.Method + " " + path + " HTTP/1.1\r\n")
	if !r.hasHeader("host") && r.Authority != "" {
		b.WriteString("Host: " + r.Authority + "\r\n")
	}
	for _, h := range r.Header {
		b.WriteString(h.Name + ": " + h.Value + "\r\n")
	}
	if !r.hasHeader("content-length") && !r.hasHeader("transfer-encoding") &&
		(len(r.Body) > 0 || methodCarriesBody(r.Method)) {
		b.WriteString("Content-Length: " + strconv.Itoa(len(r.Body)) + "\r\n")
	}
	b.WriteString("\r\n")
	b.Write(r.Body)
	return []byte(b.String())
}

// DumpH2 renders r as the HTTP/2 header list plus body, for evidence.
func (r Request) DumpH2() string {
	var b strings.Builder
	b.WriteString(":method: " + r.Method + "\r\n")
	b.WriteString(":scheme: " + r.Scheme + "\r\n")
	b.WriteString(":authority: " + r.Authority + "\r\n")
	b.WriteString(":path: " + r.Path + "\r\n")
	for _, h := range r.Header {
		b.WriteString(strings.ToLower(h.Name) + ": " + h.Value + "\r\n")
	}
	b.WriteString("\r\n")
	b.Write(r.Body)
	return b.String()
}

func methodCarriesBody(m string) bool {
	switch strings.ToUpper(m) {
	case "POST", "PUT", "PATCH":
		return true
	}
	return false
}

// Response is one answer. Err is set when no complete response arrived
// (timeout, stream reset, refused); Status may still be set when headers
// arrived before the failure.
type Response struct {
	Proto     string // "HTTP/2.0" or "HTTP/1.1"
	Status    int
	Header    http.Header
	Body      []byte
	Truncated bool
	// Elapsed runs from the moment the request's final byte left to the
	// arrival of its response headers (or the failure).
	Elapsed time.Duration
	Err     error
}

// Dump renders the response for evidence: status line, sorted headers, body.
func (r Response) Dump() string {
	var b strings.Builder
	proto := r.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	if r.Status == 0 {
		fmt.Fprintf(&b, "(no response: %v)", r.Err)
		return b.String()
	}
	fmt.Fprintf(&b, "%s %d %s\r\n", proto, r.Status, http.StatusText(r.Status))
	keys := make([]string, 0, len(r.Header))
	for k := range r.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range r.Header[k] {
			b.WriteString(k + ": " + v + "\r\n")
		}
	}
	b.WriteString("\r\n")
	b.Write(r.Body)
	return b.String()
}

// Options tunes one exchange. The zero value is usable.
type Options struct {
	// Timeout bounds the whole exchange: dial, handshake, writes and reads.
	// Zero means 10s.
	Timeout time.Duration
	// ProxyURL, when set, tunnels the connection through an HTTP CONNECT
	// proxy (http://[user:pass@]host:port).
	ProxyURL string
	// MaxBody caps how much of each response body is kept. Zero means 1 MiB.
	MaxBody int
	// Settle is the pause between priming every request and releasing the
	// final bytes, giving the server time to parse headers and block on the
	// body. Zero sends the final batch immediately.
	Settle time.Duration
}

func (o Options) timeout() time.Duration {
	if o.Timeout > 0 {
		return o.Timeout
	}
	return defaultTimeout
}

func (o Options) maxBody() int {
	if o.MaxBody > 0 {
		return o.MaxBody
	}
	return defaultMaxBody
}

// EnvProxyURL returns the proxy the shared Requester would fall back to when
// no --proxy flag is given: HTTP_PROXY, http_proxy, HTTPS_PROXY, https_proxy,
// first non-empty wins (pkg/http getProxyURL uses the same order). Modules use
// it because the --proxy value itself is not exposed to them.
func EnvProxyURL() string {
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}
