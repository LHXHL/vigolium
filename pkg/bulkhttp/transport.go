package bulkhttp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/proxytarget"
	"github.com/vigolium/vigolium/pkg/tlsprobe"
)

// Mode selects which protocols a Transport may use.
type Mode string

const (
	// ModeAuto prefers HTTP/3, then HTTP/2, then HTTP/1.1, per origin.
	ModeAuto Mode = "auto"
	// ModeHTTP1 never negotiates anything but HTTP/1.1.
	ModeHTTP1 Mode = "http1"
	// ModeHTTP2 stays on TCP and uses HTTP/2 wherever ALPN selects it.
	ModeHTTP2 Mode = "http2"
	// ModeHTTP3 requires HTTP/3: a request to an origin that cannot speak it
	// fails instead of falling back.
	ModeHTTP3 Mode = "http3"
)

// ParseMode reads a protocol mode name. Empty means ModeAuto.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto":
		return ModeAuto, nil
	case "http1", "http1.1", "1", "1.1", "h1":
		return ModeHTTP1, nil
	case "http2", "2", "h2":
		return ModeHTTP2, nil
	case "http3", "3", "h3":
		return ModeHTTP3, nil
	}
	return "", fmt.Errorf("unknown protocol %q (want auto, http1, http2 or http3)", s)
}

// Protocol is the HTTP version an origin's requests use.
type Protocol string

const (
	ProtoUnknown Protocol = ""
	ProtoHTTP1   Protocol = "http/1.1"
	ProtoHTTP2   Protocol = "h2"
	ProtoHTTP3   Protocol = "h3"
)

// Multiplexed reports whether p carries concurrent requests on one connection.
func (p Protocol) Multiplexed() bool { return p == ProtoHTTP2 || p == ProtoHTTP3 }

const (
	defaultProbeTimeout   = 2 * time.Second
	defaultStreamsPerConn = 100
	defaultMaxH3Conns     = 8
	// h3HandshakeIdleTimeout is quic-go's own handshake bound; every dial
	// also carries a shorter context deadline (ProbeTimeout, redialTimeout).
	h3HandshakeIdleTimeout = 10 * time.Second
	// minRedialTimeout floors redialTimeout.
	minRedialTimeout = 3 * time.Second
	// minProbeGrace is the least time the HTTP/3 probe gets after the racing
	// TCP handshake completes (see raceTCP).
	minProbeGrace = 200 * time.Millisecond
	// demoteAfter is how many consecutive connection-level HTTP/3 failures
	// demote an origin to TCP in ModeAuto.
	demoteAfter = 3
)

// Config configures a Transport.
type Config struct {
	// Base is the HTTP/1.1 transport template. Its Proxy, DialContext,
	// TLSClientConfig, timeouts and idle-pool sizes carry over to every
	// protocol. It is cloned, never used or mutated.
	Base *http.Transport
	// Mode is the protocol policy; empty is ModeAuto.
	Mode Mode
	// ProbeTimeout bounds the HTTP/3 proof (QUIC handshake plus the server's
	// SETTINGS). Default 2s.
	ProbeTimeout time.Duration
	// StreamsPerConn caps concurrent requests on one HTTP/3 connection.
	// Default 100, the common server MAX_STREAMS; a peer that allows fewer
	// simply makes the excess wait inside quic-go.
	StreamsPerConn int
	// MaxH3Conns caps HTTP/3 connections per origin. Default 8.
	MaxH3Conns int
	// ResolveAddr, when set, maps a "host:port" to the "ip:port" to dial for
	// HTTP/3 (curl --resolve). The TCP side applies its own mapping in
	// Base.DialContext.
	ResolveAddr func(hostPort string) string
}

// Transport is an http.RoundTripper that multiplexes requests over HTTP/2 or
// HTTP/3 where the origin supports it. See the package documentation.
type Transport struct {
	cfg Config

	// tcp carries every TCP request (HTTP/2 where ALPN selects it, unless the
	// mode is ModeHTTP1); h1 is the HTTP/1.1-only transport for requests whose
	// meaning needs it.
	tcp, h1         http.RoundTripper
	tcpBase, h1Base *http.Transport

	h3TLS    *tls.Config
	quicConf *quic.Config
	// h3Template carries the per-connection HTTP/3 settings handed to
	// NewClientConn; its own connection cache is never used.
	h3Template *http3.Transport

	origins sync.Map // origin key -> *origin
	closed  atomic.Bool
}

// New builds a Transport. cfg.Base may be nil (a zero http.Transport).
func New(cfg Config) *Transport {
	if cfg.Base == nil {
		cfg.Base = &http.Transport{}
	}
	if cfg.Mode == "" {
		cfg.Mode = ModeAuto
	}
	if cfg.ProbeTimeout <= 0 {
		cfg.ProbeTimeout = defaultProbeTimeout
	}
	if cfg.StreamsPerConn <= 0 {
		cfg.StreamsPerConn = defaultStreamsPerConn
	}
	if cfg.MaxH3Conns <= 0 {
		cfg.MaxH3Conns = defaultMaxH3Conns
	}

	t := &Transport{cfg: cfg}
	t.h1Base = tcpTransport(cfg.Base, false)
	t.h1 = proxytarget.Wrap(t.h1Base)
	if cfg.Mode == ModeHTTP1 {
		t.tcpBase, t.tcp = t.h1Base, t.h1
	} else {
		t.tcpBase = tcpTransport(cfg.Base, true)
		t.tcp = proxytarget.Wrap(t.tcpBase)
	}

	t.h3TLS = quicTLSConfig(cfg.Base.TLSClientConfig)
	t.quicConf = &quic.Config{
		HandshakeIdleTimeout: h3HandshakeIdleTimeout,
		MaxIdleTimeout:       30 * time.Second,
		// Keeps NAT bindings alive between bursts of a long scan.
		KeepAlivePeriod: 10 * time.Second,
	}
	t.h3Template = &http3.Transport{
		MaxResponseHeaderBytes: int(cfg.Base.MaxResponseHeaderBytes),
		DisableCompression:     cfg.Base.DisableCompression,
	}
	return t
}

// tcpTransport clones base for TCP use, with HTTP/2 negotiated through ALPN
// when allowH2 and strictly HTTP/1.1 otherwise.
func tcpTransport(base *http.Transport, allowH2 bool) *http.Transport {
	t := base.Clone()
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	if allowH2 {
		protocols.SetHTTP2(true)
		// Detect a dead HTTP/2 connection (a middlebox that dropped it) with a
		// PING instead of waiting for every stream on it to time out.
		t.HTTP2 = &http.HTTP2Config{SendPingTimeout: 30 * time.Second, PingTimeout: 15 * time.Second}
	} else {
		// The documented way to keep a transport off HTTP/2 even when its
		// TLSClientConfig would let ALPN pick it.
		t.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	t.Protocols = protocols
	t.ForceAttemptHTTP2 = allowH2
	return t
}

// quicTLSConfig derives the HTTP/3 TLS config from the TCP one: same
// verification stance and client certificates, ALPN h3, TLS 1.3 (QUIC's only
// version). It has its own session cache: a ticket from a TCP handshake is
// not a QUIC session.
func quicTLSConfig(base *tls.Config) *tls.Config {
	var cfg *tls.Config
	if base != nil {
		cfg = base.Clone()
	} else {
		cfg = &tls.Config{} //nolint:gosec // verification follows the caller's TCP config
	}
	cfg.NextProtos = []string{http3.NextProtoH3}
	cfg.MinVersion = tls.VersionTLS13
	cfg.MaxVersion = 0
	cfg.CipherSuites = nil
	cfg.Renegotiation = tls.RenegotiateNever
	cfg.ClientSessionCache = tls.NewLRUClientSessionCache(256)
	return cfg
}

// origin is one scheme://host:port's protocol decision and HTTP/3 pool.
type origin struct {
	key   string
	ready chan struct{} // closed once proto/pool/reason are set

	// Set once before ready closes. pool is non-nil exactly when the origin
	// proved HTTP/3.
	reason string // why the origin is not on HTTP/3 (for reporting)
	pool   *h3Pool

	demoted  atomic.Bool
	h3Fails  atomic.Int32
	tcpProto atomic.Value // Protocol last observed on a TCP response
}

// onH3 reports whether o's requests go over HTTP/3. Valid once ready closed.
func (o *origin) onH3() bool { return o.pool != nil && !o.demoted.Load() }

// h3RequiredErr is the ModeHTTP3 refusal for an origin without HTTP/3.
func (o *origin) h3RequiredErr() error {
	return fmt.Errorf("bulkhttp: HTTP/3 required but unavailable for %s: %s", o.key, o.reason)
}

func originKey(u *url.URL) string {
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(hostPort(u))
}

func hostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		if strings.EqualFold(u.Scheme, "https") {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil {
		return nil, errors.New("bulkhttp: request has no URL")
	}
	// Under ModeHTTP1 the TCP transport is the HTTP/1.1 one already.
	if t.cfg.Mode != ModeHTTP1 && RequiresHTTP1(req.Header) != "" {
		return t.h1.RoundTrip(req)
	}
	o, err := t.originFor(req)
	if err != nil {
		return nil, err
	}
	if o.onH3() {
		return t.roundTripH3(o, req)
	}
	if t.cfg.Mode == ModeHTTP3 {
		return nil, o.h3RequiredErr()
	}
	return t.roundTripTCP(o, req)
}

func (t *Transport) roundTripTCP(o *origin, req *http.Request) (*http.Response, error) {
	resp, err := t.tcp.RoundTrip(req)
	if err == nil && o != nil {
		o.tcpProto.Store(protoOf(resp))
	}
	return resp, err
}

func protoOf(resp *http.Response) Protocol {
	switch resp.ProtoMajor {
	case 2:
		return ProtoHTTP2
	case 3:
		return ProtoHTTP3
	}
	return ProtoHTTP1
}

// roundTripH3 sends req on the origin's HTTP/3 pool. A request that failed
// because its connection was unusable or died is retried once when that is
// safe: always when no stream was opened (nothing reached the server), and
// for a replayable idempotent request otherwise. The retry goes to a fresh
// HTTP/3 connection, or to TCP once the origin has been demoted.
func (t *Transport) roundTripH3(o *origin, req *http.Request) (*http.Response, error) {
	resp, err := o.pool.roundTrip(req)
	if err == nil {
		o.h3Fails.Store(0)
		return resp, nil
	}
	var cerr *connError
	if !errors.As(err, &cerr) || req.Context().Err() != nil {
		return nil, err
	}
	if n := o.h3Fails.Add(1); (n >= demoteAfter || cerr.dial) && t.cfg.Mode == ModeAuto {
		t.demote(o, err)
	}
	if !cerr.unsent && !replayable(req) {
		return nil, err
	}
	retry, rerr := rewind(req)
	if rerr != nil {
		return nil, err
	}
	if o.demoted.Load() {
		return t.roundTripTCP(o, retry)
	}
	resp, err = o.pool.roundTrip(retry)
	if err == nil {
		o.h3Fails.Store(0)
	}
	return resp, err
}

// redialTimeout bounds a pool-growth or replacement dial on an origin that
// has already proven HTTP/3: twice the probe's budget, so a healthy but slow
// path still connects while a dead one is noticed in seconds, not tens.
func (t *Transport) redialTimeout() time.Duration {
	return max(2*t.cfg.ProbeTimeout, minRedialTimeout)
}

// demote moves o to TCP for the rest of the Transport's life.
func (t *Transport) demote(o *origin, cause error) {
	if !o.demoted.CompareAndSwap(false, true) {
		return
	}
	zap.L().Warn("HTTP/3 connections to the origin keep failing; continuing over TCP",
		zap.String("origin", o.key), zap.Error(cause))
	o.pool.close()
}

// replayable reports whether req may be sent again after its connection died
// mid-request: an idempotent method whose body can be rebuilt.
func replayable(req *http.Request) bool {
	switch req.Method {
	case "", http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
	default:
		return false
	}
	return req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
}

// rewind returns req ready to be sent again, with a fresh body.
func rewind(req *http.Request) (*http.Request, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return req, nil
	}
	if req.GetBody == nil {
		return nil, errors.New("body cannot be replayed")
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	out := *req
	out.Body = body
	return &out, nil
}

// originFor returns req's origin, deciding its protocol on first use. The
// decision blocks the origin's first requests (bounded by ProbeTimeout) so
// that no request goes out before the protocol is fixed.
func (t *Transport) originFor(req *http.Request) (*origin, error) {
	if t.closed.Load() {
		return nil, errors.New("bulkhttp: transport closed")
	}
	key := originKey(req.URL)
	v, ok := t.origins.Load(key)
	if !ok {
		var loaded bool
		v, loaded = t.origins.LoadOrStore(key, &origin{key: key, ready: make(chan struct{})})
		if !loaded {
			t.resolve(v.(*origin), req)
		}
	}
	o := v.(*origin)
	select {
	case <-o.ready:
		return o, nil
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
}

// resolve decides o's protocol and closes o.ready. It runs once per origin, on
// the goroutine of the origin's first request.
func (t *Transport) resolve(o *origin, req *http.Request) {
	defer close(o.ready)
	if reason := t.h3Ineligible(req); reason != "" {
		o.reason = reason
		return
	}
	// The probe's own context: the first request's cancellation must not
	// decide the protocol for every later request to the origin.
	ctx, cancel := context.WithTimeout(context.Background(), t.cfg.ProbeTimeout)
	defer cancel()
	if t.cfg.Mode == ModeAuto {
		go t.raceTCP(ctx, cancel, o, req)
	}
	pool := newH3Pool(t, req.URL)
	if err := pool.probe(ctx); err != nil {
		o.reason = "HTTP/3 probe failed: " + err.Error()
		pool.close()
		return
	}
	o.pool = pool
}

// raceTCP runs the TCP/TLS handshake alongside the QUIC probe and, once it
// completes, gives QUIC as long again (at least minProbeGrace) before calling
// cancel. A TCP+TLS handshake is two round trips and a QUIC handshake one, so
// a probe that has not answered by then is not coming: a host without HTTP/3,
// or a network dropping UDP, no longer costs the full ProbeTimeout on every
// origin's first request. The handshake's ALPN result is recorded as the
// origin's TCP protocol, which Prepare reports.
func (t *Transport) raceTCP(ctx context.Context, cancel context.CancelFunc, o *origin, req *http.Request) {
	start := time.Now()
	p := t.alpnProbe(ctx, req)
	if p == ProtoUnknown {
		return
	}
	o.tcpProto.Store(p)
	time.AfterFunc(max(time.Since(start), minProbeGrace), cancel)
}

// h3Ineligible says why req's origin cannot use HTTP/3 under this transport,
// or "" when it may try.
func (t *Transport) h3Ineligible(req *http.Request) string {
	switch t.cfg.Mode {
	case ModeHTTP1, ModeHTTP2:
		return "protocol mode " + string(t.cfg.Mode)
	}
	if !strings.EqualFold(req.URL.Scheme, "https") {
		return "HTTP/3 needs an https origin"
	}
	if t.proxied(req) {
		return "a proxy applies (a direct QUIC connection would bypass it)"
	}
	return ""
}

// proxied reports whether the base transport sends req through a proxy.
func (t *Transport) proxied(req *http.Request) bool {
	proxy := t.cfg.Base.Proxy
	if proxy == nil {
		return false
	}
	u, err := proxy(req)
	return err != nil || u != nil
}

// Prepare decides u's protocol without sending an HTTP request and returns it:
// the HTTP/3 probe when eligible, else a TLS handshake that reads the ALPN
// result (direct https origins only). A proxied TCP origin reports
// ProtoUnknown until its first response.
func (t *Transport) Prepare(ctx context.Context, u *url.URL) (Protocol, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return ProtoUnknown, err
	}
	o, err := t.originFor(req)
	if err != nil {
		return ProtoUnknown, err
	}
	if o.onH3() {
		return ProtoHTTP3, nil
	}
	if t.cfg.Mode == ModeHTTP3 {
		return ProtoUnknown, o.h3RequiredErr()
	}
	if p, _ := o.tcpProto.Load().(Protocol); p != ProtoUnknown {
		return p, nil
	}
	p := t.alpnProbe(ctx, req)
	if p != ProtoUnknown {
		o.tcpProto.Store(p)
	}
	return p, nil
}

// alpnProbe handshakes TLS with u's origin to read which protocol ALPN
// selects. http:// is HTTP/1.1; a proxied origin is left unknown.
func (t *Transport) alpnProbe(ctx context.Context, req *http.Request) Protocol {
	if !strings.EqualFold(req.URL.Scheme, "https") || t.cfg.Mode == ModeHTTP1 {
		return ProtoHTTP1
	}
	if t.proxied(req) {
		return ProtoUnknown
	}
	dial := t.tcpBase.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: 10 * time.Second}).DialContext
	}
	addr := hostPort(req.URL)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := dial(ctx, "tcp", addr)
	if err != nil {
		return ProtoUnknown
	}
	defer func() { _ = raw.Close() }()
	cfg := t.tcpTLSConfig(req.URL.Hostname())
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		return ProtoUnknown
	}
	if conn.ConnectionState().NegotiatedProtocol == "h2" {
		return ProtoHTTP2
	}
	return ProtoHTTP1
}

func (t *Transport) tcpTLSConfig(host string) *tls.Config {
	var cfg *tls.Config
	if t.tcpBase.TLSClientConfig != nil {
		cfg = t.tcpBase.TLSClientConfig.Clone()
	} else {
		cfg = &tls.Config{} //nolint:gosec // verification follows the caller's TCP config
	}
	cfg.NextProtos = []string{"h2", "http/1.1"}
	if cfg.ServerName == "" {
		cfg.ServerName = tlsprobe.SNIName(host)
	}
	return cfg
}

// Protocol reports the protocol u's origin is using: HTTP/3 once pinned and
// not demoted, else the protocol of its last TCP response, else
// ProtoUnknown.
func (t *Transport) Protocol(u *url.URL) Protocol {
	v, ok := t.origins.Load(originKey(u))
	if !ok {
		return ProtoUnknown
	}
	o := v.(*origin)
	select {
	case <-o.ready:
	default:
		return ProtoUnknown
	}
	if o.onH3() {
		return ProtoHTTP3
	}
	p, _ := o.tcpProto.Load().(Protocol)
	return p
}

// CloseIdleConnections closes idle TCP connections and HTTP/3 connections
// with no request in flight.
func (t *Transport) CloseIdleConnections() {
	t.h1Base.CloseIdleConnections()
	if t.tcpBase != t.h1Base {
		t.tcpBase.CloseIdleConnections()
	}
	for _, o := range t.snapshotOrigins() {
		if o.pool != nil {
			o.pool.closeIdle()
		}
	}
}

// Close closes every connection. Requests in flight fail; later requests are
// refused.
func (t *Transport) Close() {
	t.closed.Store(true)
	t.CloseIdleConnections()
	for _, o := range t.snapshotOrigins() {
		if o.pool != nil {
			o.pool.close()
		}
	}
}

// snapshotOrigins returns the origins whose protocol is decided.
func (t *Transport) snapshotOrigins() []*origin {
	var ready []*origin
	t.origins.Range(func(_, v any) bool {
		o := v.(*origin)
		select {
		case <-o.ready:
			ready = append(ready, o)
		default:
		}
		return true
	})
	return ready
}

// RequiresHTTP1 reports why a request with header h must be sent as
// HTTP/1.1, or "" when any protocol carries it faithfully. HTTP/2 and HTTP/3
// forbid connection-specific header fields (RFC 9113 §8.2.2, RFC 9114 §4.2)
// and Go's and quic-go's encoders silently drop them, so only the ones whose
// loss changes what the server sees force HTTP/1.1:
//
//   - Upgrade (a protocol switch: WebSocket, h2c);
//   - Transfer-Encoding left in the header map (net/http lifts chunked into
//     Request.TransferEncoding; anything still here is deliberate);
//   - TE other than "trailers";
//   - Connection naming anything but keep-alive/close: it nominates headers
//     for a proxy to strip, the hop-by-hop abuse a request may be probing.
//
// Connection: keep-alive/close, Keep-Alive and Proxy-Connection are pure
// HTTP/1.x connection management - every browser and proxy drops them when
// it speaks HTTP/2 - and a captured request almost always carries one, so
// they do not hold a request on HTTP/1.1.
//
// h's keys must be canonical, as net/http builds them.
func RequiresHTTP1(h http.Header) string {
	if len(h["Upgrade"]) > 0 {
		return "carries an Upgrade header"
	}
	if len(h["Transfer-Encoding"]) > 0 {
		return "carries a Transfer-Encoding header"
	}
	for _, v := range h["Te"] {
		if !strings.EqualFold(strings.TrimSpace(v), "trailers") {
			return "carries a TE header other than trailers"
		}
	}
	for _, v := range h["Connection"] {
		for rest := v; rest != ""; {
			var tok string
			tok, rest, _ = strings.Cut(rest, ",")
			tok = strings.TrimSpace(tok)
			if tok != "" && !strings.EqualFold(tok, "keep-alive") && !strings.EqualFold(tok, "close") {
				return "names hop-by-hop headers in Connection"
			}
		}
	}
	return ""
}
