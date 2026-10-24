package bulkhttp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/vigolium/vigolium/pkg/tlsprobe"
)

// connError marks an HTTP/3 failure of the connection rather than of the
// request: the dial failed, no stream could be opened, or the connection died
// while the request was on it. unsent means the request never reached a
// stream, so retrying it cannot duplicate it at the server.
type connError struct {
	err    error
	unsent bool
	// dial means a new connection could not be established. For an origin
	// that already proved HTTP/3 that is not a transient stream failure: QUIC
	// to the origin has stopped working (UDP blocked mid-run, the server
	// dropped HTTP/3), so the origin is demoted at once.
	dial bool
}

// connUnusableText is how quic-go's http3 client words a request that never
// got a stream (its errConnUnusable is unexported). TestConnUnusableText pins
// it, so a quic-go upgrade that rewords it fails a test rather than silently
// turning GOAWAY retirement into hard errors.
const connUnusableText = "http3: conn unusable"

func (e *connError) Error() string { return e.err.Error() }
func (e *connError) Unwrap() error { return e.err }

// h3Conn is one owned QUIC connection and its HTTP/3 client.
type h3Conn struct {
	qc *quic.Conn
	cc *http3.ClientConn

	// Guarded by the pool's mu.
	inFlight int
	retiring bool // accepts no new requests; closed when inFlight drains
}

// h3Pool is one origin's HTTP/3 connections. Admission is a token per
// in-flight request (StreamsPerConn × MaxH3Conns in total); within that, a
// request takes the least-loaded live connection with room, and a connection
// is dialed only when every live one is full.
type h3Pool struct {
	t          *Transport
	addr       string // host:port the origin names
	serverName string

	tokens chan struct{}
	dialMu sync.Mutex // one dial at a time per origin

	mu     sync.Mutex
	conns  []*h3Conn
	closed bool
}

func newH3Pool(t *Transport, u *url.URL) *h3Pool {
	p := &h3Pool{
		t:      t,
		addr:   hostPort(u),
		tokens: make(chan struct{}, t.cfg.StreamsPerConn*t.cfg.MaxH3Conns),
	}
	p.serverName = tlsprobe.SNIName(u.Hostname())
	if t.h3TLS.ServerName != "" {
		p.serverName = t.h3TLS.ServerName
	}
	return p
}

// probe proves the origin speaks HTTP/3: a QUIC handshake negotiating ALPN h3
// and the server's SETTINGS frame, within ctx. The proven connection stays in
// the pool as its first connection.
func (p *h3Pool) probe(ctx context.Context) error {
	c, err := p.dial(ctx)
	if err != nil {
		return err
	}
	select {
	case <-c.cc.ReceivedSettings():
	case <-ctx.Done():
		p.discard(c)
		return fmt.Errorf("no HTTP/3 SETTINGS from the server: %w", ctx.Err())
	case <-c.qc.Context().Done():
		p.discard(c)
		return fmt.Errorf("connection closed before SETTINGS: %w", context.Cause(c.qc.Context()))
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		p.discard(c)
		return errPoolClosed()
	}
	p.conns = append(p.conns, c)
	return nil
}

// dial opens one QUIC connection on its own UDP socket. Each connection having
// its own socket and quic.Transport is what lets several connections process
// packets in parallel, and it ties the socket's lifetime to the connection's.
func (p *h3Pool) dial(ctx context.Context) (*h3Conn, error) {
	udpAddr, err := p.resolve(ctx)
	if err != nil {
		return nil, err
	}
	network := "udp4"
	if udpAddr.IP.To4() == nil {
		network = "udp6"
	}
	pc, err := net.ListenUDP(network, nil)
	if err != nil {
		return nil, err
	}
	tr := &quic.Transport{Conn: pc}
	release := func() {
		_ = tr.Close()
		_ = pc.Close()
	}
	tlsConf := p.t.h3TLS.Clone()
	tlsConf.ServerName = p.serverName
	qc, err := tr.Dial(ctx, udpAddr, tlsConf, p.t.quicConf)
	if err != nil {
		release()
		return nil, err
	}
	if proto := qc.ConnectionState().TLS.NegotiatedProtocol; proto != http3.NextProtoH3 {
		_ = qc.CloseWithError(0, "")
		release()
		return nil, fmt.Errorf("server negotiated ALPN %q, not h3", proto)
	}
	c := &h3Conn{qc: qc, cc: p.t.h3Template.NewClientConn(qc)}
	go func() {
		<-qc.Context().Done()
		p.retire(c)
		release()
	}()
	return c, nil
}

// resolve turns the origin's host:port into the UDP address to dial,
// applying Config.ResolveAddr first.
func (p *h3Pool) resolve(ctx context.Context) (*net.UDPAddr, error) {
	addr := p.addr
	if m := p.t.cfg.ResolveAddr; m != nil {
		if mapped := m(addr); mapped != "" {
			addr = mapped
		}
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip.Unmap(), mustPort(port))), nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for %s", host)
	}
	ip := ips[0]
	for _, cand := range ips {
		if cand.Is4() || cand.Is4In6() {
			ip = cand
			break
		}
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip.Unmap(), mustPort(port))), nil
}

// mustPort parses a port that net.SplitHostPort produced; an unparseable one
// becomes 0, which the dial then refuses.
func mustPort(s string) uint16 {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(n)
}

// discard closes a connection that never joined the pool.
func (p *h3Pool) discard(c *h3Conn) {
	_ = c.qc.CloseWithError(0, "")
}

// roundTrip sends req on a pooled connection. The connection's slot is held
// until the response body is closed (or fully read).
func (p *h3Pool) roundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	select {
	case p.tokens <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	c, err := p.pick(ctx)
	if err != nil {
		<-p.tokens
		return nil, err
	}
	// quic-go starts a body-copy goroutine (with its own buffer) for any
	// non-nil Body, and http.NoBody is non-nil.
	if req.Body == http.NoBody {
		r := *req
		r.Body = nil
		req = &r
	}
	resp, err := c.cc.RoundTrip(req)
	if err != nil {
		unsent := strings.Contains(err.Error(), connUnusableText)
		dead := c.qc.Context().Err() != nil
		if unsent {
			// A GOAWAY or an exhausted stream budget: the connection takes
			// no new requests, though its in-flight ones may still finish.
			p.markRetiring(c)
		}
		p.release(c)
		if unsent || dead {
			return nil, &connError{err: err, unsent: unsent}
		}
		return nil, err
	}
	resp.Body = &streamBody{ReadCloser: resp.Body, done: func() { p.release(c) }}
	return resp, nil
}

// pick reserves a slot on the least-loaded live connection with room,
// dialing a new connection when all are full.
func (p *h3Pool) pick(ctx context.Context) (*h3Conn, error) {
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, errPoolClosed()
		}
		best, live := p.leastLoadedLocked()
		if best != nil {
			best.inFlight++
			p.mu.Unlock()
			return best, nil
		}
		p.mu.Unlock()

		if live >= p.t.cfg.MaxH3Conns {
			// Only reachable while retiring connections still hold tokens;
			// wait for them to drain rather than exceed the cap.
			select {
			case <-time.After(5 * time.Millisecond):
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if err := p.grow(ctx, live); err != nil {
			return nil, err
		}
	}
}

// leastLoadedLocked returns the live connection with the most room (nil when
// every live one is full) and how many live connections there are. p.mu held.
func (p *h3Pool) leastLoadedLocked() (best *h3Conn, live int) {
	for _, c := range p.conns {
		if c.retiring {
			continue
		}
		live++
		if c.inFlight < p.t.cfg.StreamsPerConn && (best == nil || c.inFlight < best.inFlight) {
			best = c
		}
	}
	return best, live
}

// grow dials one more connection unless another caller already did while
// this one waited for the dial lock.
func (p *h3Pool) grow(ctx context.Context, sawLive int) error {
	p.dialMu.Lock()
	defer p.dialMu.Unlock()
	p.mu.Lock()
	best, live := p.leastLoadedLocked()
	closed := p.closed
	p.mu.Unlock()
	switch {
	case closed:
		// Demoted while this caller waited for the dial lock.
		return errPoolClosed()
	case best != nil || live > sawLive:
		return nil
	}
	dctx, cancel := context.WithTimeout(ctx, p.t.redialTimeout())
	defer cancel()
	c, err := p.dial(dctx)
	if err != nil {
		return &connError{err: fmt.Errorf("bulkhttp: HTTP/3 dial %s: %w", p.addr, err), unsent: true, dial: true}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		p.discard(c)
		return errPoolClosed()
	}
	p.conns = append(p.conns, c)
	return nil
}

// errPoolClosed refuses a request on a closed (or demoted) pool; nothing was
// sent, so the caller may retry it elsewhere.
func errPoolClosed() error {
	return &connError{err: errors.New("bulkhttp: HTTP/3 pool closed"), unsent: true}
}

// release returns a request's slot.
func (p *h3Pool) release(c *h3Conn) {
	p.mu.Lock()
	c.inFlight--
	closeNow := c.retiring && c.inFlight == 0
	p.mu.Unlock()
	if closeNow {
		_ = c.qc.CloseWithError(0, "")
	}
	<-p.tokens
}

// markRetiring stops new requests from choosing c.
func (p *h3Pool) markRetiring(c *h3Conn) {
	p.mu.Lock()
	c.retiring = true
	p.mu.Unlock()
}

// retire removes exactly c from the pool once its connection has died. It is
// keyed by identity, so a late notice from a dead connection cannot remove
// the healthy one that replaced it.
func (p *h3Pool) retire(c *h3Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c.retiring = true
	for i, cur := range p.conns {
		if cur == c {
			p.conns = append(p.conns[:i], p.conns[i+1:]...)
			return
		}
	}
}

// closeIdle closes connections with nothing in flight.
func (p *h3Pool) closeIdle() {
	p.mu.Lock()
	var idle []*h3Conn
	for _, c := range p.conns {
		if c.inFlight == 0 {
			c.retiring = true
			idle = append(idle, c)
		}
	}
	p.mu.Unlock()
	for _, c := range idle {
		_ = c.qc.CloseWithError(0, "")
	}
}

// close closes every connection and refuses new requests.
func (p *h3Pool) close() {
	p.mu.Lock()
	p.closed = true
	conns := append([]*h3Conn(nil), p.conns...)
	for _, c := range conns {
		c.retiring = true
	}
	p.mu.Unlock()
	for _, c := range conns {
		_ = c.qc.CloseWithError(0, "")
	}
}

// streamBody releases the request's pool slot exactly once, on Close or when
// the body has been read to its end.
type streamBody struct {
	io.ReadCloser
	once sync.Once
	done func()
}

func (b *streamBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.once.Do(b.done)
	}
	return n, err
}

func (b *streamBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.done)
	return err
}
