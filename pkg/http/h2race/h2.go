package h2race

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	// initialConnWindow is the RFC 9113 connection-level send window every
	// peer starts with; only a WINDOW_UPDATE on stream 0 raises it.
	initialConnWindow = 65535
	// recvWindow is the receive window this client advertises, per stream and
	// for the connection, so response bodies flow without per-frame updates.
	recvWindow = 4 << 20
	// maxHandshakeFrames bounds how many frames are read waiting for the
	// server's first SETTINGS.
	maxHandshakeFrames = 16
	// writeBufferSize holds every priming frame of a batch so it leaves in as
	// few writes as the TLS layer allows.
	writeBufferSize = 256 << 10
)

// SinglePacket sends reqs as concurrent streams on one HTTP/2 connection and
// releases their final DATA frames in a single write, so a server that waits
// for each body to complete sees every request finish inside one packet.
//
// Every request's HEADERS (and every body byte but the last) go out first
// with END_STREAM withheld. After opts.Settle the last byte of each body (or an
// empty DATA frame for a bodyless request) is framed with END_STREAM into one
// buffer and written with one Write call.
//
// The returned slice is index-aligned with reqs. A connection-level failure
// (dial, ALPN without h2, settings that cannot fit the batch) is returned as
// the error with a nil slice; ErrNotH2 tells the caller to use LastByteSync.
func SinglePacket(ctx context.Context, t Target, reqs []Request, opts Options) ([]Response, error) {
	if len(reqs) == 0 {
		return nil, nil
	}
	if !t.TLS {
		return nil, ErrNotH2
	}
	// Offer http/1.1 too: a server with no h2 then completes the handshake
	// (instead of failing it with no_application_protocol) and the caller
	// gets a clean ErrNotH2.
	conn, proto, err := dial(ctx, t, opts, []string{"h2", "http/1.1"})
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if proto != "h2" {
		return nil, ErrNotH2
	}
	_ = conn.SetDeadline(time.Now().Add(opts.timeout()))

	done := make(chan struct{})
	defer close(done)
	watchContext(ctx, done, conn)

	c := newH2Conn(conn)
	if err := c.handshake(); err != nil {
		return nil, err
	}
	if uint32(len(reqs)) > c.peerMaxStreams {
		return nil, fmt.Errorf("%w (%d > %d)", ErrTooManyStreams, len(reqs), c.peerMaxStreams)
	}
	total := 0
	for _, r := range reqs {
		if len(r.Body) > int(c.peerInitWindow) {
			return nil, ErrBodyTooLarge
		}
		total += len(r.Body)
	}
	if total > initialConnWindow {
		return nil, ErrBodyTooLarge
	}

	streams := make([]*h2stream, len(reqs))
	for i := range reqs {
		streams[i] = &h2stream{id: uint32(2*i + 1)}
	}

	// The reader runs from before the first HEADERS so an early RST_STREAM,
	// PING or SETTINGS is answered while the batch is being primed.
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		c.readLoop(streams, opts.maxBody())
	}()

	if err := c.prime(reqs, streams); err != nil {
		_ = conn.Close()
		<-readerDone
		return nil, err
	}
	if opts.Settle > 0 {
		select {
		case <-time.After(opts.Settle):
		case <-ctx.Done():
		}
	}
	if err := c.release(reqs, streams); err != nil {
		_ = conn.Close()
		<-readerDone
		return nil, err
	}
	<-readerDone

	out := make([]Response, len(reqs))
	for i, st := range streams {
		out[i] = st.response()
	}
	return out, nil
}

// h2conn is one client connection. All frame writes go through wmu.
type h2conn struct {
	conn net.Conn
	bw   *bufio.Writer
	fr   *http2.Framer

	wmu    sync.Mutex
	hbuf   bytes.Buffer
	encode *hpack.Encoder

	peerMaxStreams uint32
	peerInitWindow uint32
	peerMaxFrame   uint32

	sentAt time.Time // when the final batch left; guarded by wmu
}

func newH2Conn(conn net.Conn) *h2conn {
	c := &h2conn{
		conn:           conn,
		bw:             bufio.NewWriterSize(conn, writeBufferSize),
		peerMaxStreams: math.MaxUint32,
		peerInitWindow: initialConnWindow,
		peerMaxFrame:   16384,
	}
	c.fr = http2.NewFramer(c.bw, bufio.NewReader(conn))
	c.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	c.fr.MaxHeaderListSize = 1 << 20
	c.encode = hpack.NewEncoder(&c.hbuf)
	return c
}

// handshake sends the preface and SETTINGS, then reads until the server's
// SETTINGS arrive and acknowledges them.
func (c *h2conn) handshake() error {
	if _, err := c.bw.WriteString(http2.ClientPreface); err != nil {
		return err
	}
	if err := c.fr.WriteSettings(
		http2.Setting{ID: http2.SettingEnablePush, Val: 0},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: recvWindow},
	); err != nil {
		return err
	}
	if err := c.fr.WriteWindowUpdate(0, recvWindow-initialConnWindow); err != nil {
		return err
	}
	if err := c.bw.Flush(); err != nil {
		return err
	}
	for i := 0; i < maxHandshakeFrames; i++ {
		f, err := c.fr.ReadFrame()
		if err != nil {
			return fmt.Errorf("h2race: handshake: %w", err)
		}
		sf, ok := f.(*http2.SettingsFrame)
		if !ok || sf.IsAck() {
			continue
		}
		_ = sf.ForeachSetting(func(s http2.Setting) error {
			switch s.ID {
			case http2.SettingMaxConcurrentStreams:
				c.peerMaxStreams = s.Val
			case http2.SettingInitialWindowSize:
				c.peerInitWindow = s.Val
			case http2.SettingMaxFrameSize:
				c.peerMaxFrame = s.Val
			}
			return nil
		})
		if err := c.fr.WriteSettingsAck(); err != nil {
			return err
		}
		return c.bw.Flush()
	}
	return errors.New("h2race: handshake: no SETTINGS from server")
}

// headerBlock HPACK-encodes r. The encoder carries dynamic-table state, so
// blocks must be encoded in the order they are sent; callers hold wmu.
func (c *h2conn) headerBlock(r Request) []byte {
	c.hbuf.Reset()
	scheme := r.Scheme
	if scheme == "" {
		scheme = "https"
	}
	path := r.Path
	if path == "" {
		path = "/"
	}
	_ = c.encode.WriteField(hpack.HeaderField{Name: ":method", Value: r.Method})
	_ = c.encode.WriteField(hpack.HeaderField{Name: ":scheme", Value: scheme})
	_ = c.encode.WriteField(hpack.HeaderField{Name: ":authority", Value: r.Authority})
	_ = c.encode.WriteField(hpack.HeaderField{Name: ":path", Value: path})
	for _, h := range r.Header {
		_ = c.encode.WriteField(hpack.HeaderField{Name: strings.ToLower(h.Name), Value: h.Value})
	}
	return append([]byte(nil), c.hbuf.Bytes()...)
}

// prime writes every stream's HEADERS and all body bytes but the last, with
// END_STREAM withheld, and flushes them.
func (c *h2conn) prime(reqs []Request, streams []*h2stream) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	maxFrame := int(c.peerMaxFrame)
	for i, r := range reqs {
		id := streams[i].id
		block := c.headerBlock(r)
		first := block
		if len(first) > maxFrame {
			first = block[:maxFrame]
		}
		if err := c.fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      id,
			BlockFragment: first,
			EndHeaders:    len(first) == len(block),
		}); err != nil {
			return err
		}
		for rest := block[len(first):]; len(rest) > 0; {
			n := min(len(rest), maxFrame)
			if err := c.fr.WriteContinuation(id, n == len(rest), rest[:n]); err != nil {
				return err
			}
			rest = rest[n:]
		}
		if len(r.Body) > 1 {
			for body := r.Body[:len(r.Body)-1]; len(body) > 0; {
				n := min(len(body), maxFrame)
				if err := c.fr.WriteData(id, false, body[:n]); err != nil {
					return err
				}
				body = body[n:]
			}
		}
	}
	return c.bw.Flush()
}

// finalBatch frames the END_STREAM DATA frame of every stream into one buffer.
func finalBatch(reqs []Request, streams []*h2stream) ([]byte, error) {
	var buf bytes.Buffer
	fr := http2.NewFramer(&buf, nil)
	for i, r := range reqs {
		var last []byte
		if len(r.Body) > 0 {
			last = r.Body[len(r.Body)-1:]
		}
		if err := fr.WriteData(streams[i].id, true, last); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// release writes the final batch with ONE Write call on the connection.
func (c *h2conn) release(reqs []Request, streams []*h2stream) error {
	batch, err := finalBatch(reqs, streams)
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := c.bw.Flush(); err != nil { // nothing may be queued ahead of the batch
		return err
	}
	c.sentAt = time.Now()
	_, err = c.conn.Write(batch)
	return err
}

func (c *h2conn) releasedAt() time.Time {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.sentAt
}

// writeLocked runs fn under wmu and flushes.
func (c *h2conn) writeLocked(fn func() error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if fn() == nil {
		_ = c.bw.Flush()
	}
}

// h2stream accumulates one stream's response. Only readLoop writes it.
type h2stream struct {
	id        uint32
	status    int
	header    http.Header
	body      []byte
	truncated bool
	headersAt time.Time
	sentAt    time.Time
	done      bool
	err       error
}

func (s *h2stream) response() Response {
	r := Response{
		Proto:     "HTTP/2.0",
		Status:    s.status,
		Header:    s.header,
		Body:      s.body,
		Truncated: s.truncated,
		Err:       s.err,
	}
	switch {
	case !s.headersAt.IsZero() && !s.sentAt.IsZero():
		r.Elapsed = s.headersAt.Sub(s.sentAt)
	case !s.sentAt.IsZero():
		r.Elapsed = time.Since(s.sentAt)
	}
	if r.Elapsed < 0 {
		r.Elapsed = 0
	}
	if !s.done && r.Err == nil {
		r.Err = ErrTimeout
	}
	return r
}

// readLoop reads frames until every stream is finished or the connection
// fails, answering SETTINGS and PING and keeping receive windows open.
func (c *h2conn) readLoop(streams []*h2stream, maxBody int) {
	byID := make(map[uint32]*h2stream, len(streams))
	for _, s := range streams {
		byID[s.id] = s
	}
	remaining := len(streams)
	finish := func(s *h2stream, err error) {
		if s.done {
			return
		}
		s.done = true
		if s.err == nil {
			s.err = err
		}
		if s.sentAt.IsZero() {
			s.sentAt = c.releasedAt()
		}
		remaining--
	}

	for remaining > 0 {
		f, err := c.fr.ReadFrame()
		if err != nil {
			var se http2.StreamError
			if errors.As(err, &se) {
				if s := byID[se.StreamID]; s != nil {
					finish(s, fmt.Errorf("%w: %v", ErrStreamReset, se.Code))
				}
				continue
			}
			fail := ErrRefused
			if errors.Is(err, os.ErrDeadlineExceeded) {
				fail = ErrTimeout
			}
			for _, s := range streams {
				if !s.done {
					// Not counted as done: response() reports ErrTimeout or
					// the error recorded here.
					s.err = fail
					if s.sentAt.IsZero() {
						s.sentAt = c.releasedAt()
					}
				}
			}
			return
		}

		switch f := f.(type) {
		case *http2.MetaHeadersFrame:
			s := byID[f.StreamID]
			if s == nil || s.done {
				continue
			}
			if s.status == 0 {
				code, _ := strconv.Atoi(f.PseudoValue("status"))
				if code >= 100 && code < 200 && !f.StreamEnded() {
					continue // informational; the real response follows
				}
				s.status = code
				s.headersAt = time.Now()
				s.sentAt = c.releasedAt()
				s.header = make(http.Header)
				for _, hf := range f.RegularFields() {
					s.header.Add(hf.Name, hf.Value)
				}
			}
			if f.StreamEnded() {
				finish(s, nil)
			}
		case *http2.DataFrame:
			data := f.Data()
			if n := uint32(len(data)); n > 0 {
				sid := f.StreamID
				ended := f.StreamEnded()
				c.writeLocked(func() error {
					if err := c.fr.WriteWindowUpdate(0, n); err != nil {
						return err
					}
					if !ended {
						return c.fr.WriteWindowUpdate(sid, n)
					}
					return nil
				})
			}
			s := byID[f.StreamID]
			if s == nil || s.done {
				continue
			}
			if room := maxBody - len(s.body); room > 0 {
				if len(data) > room {
					data = data[:room]
					s.truncated = true
				}
				s.body = append(s.body, data...)
			} else if len(data) > 0 {
				s.truncated = true
			}
			if f.StreamEnded() {
				finish(s, nil)
			}
		case *http2.RSTStreamFrame:
			if s := byID[f.StreamID]; s != nil {
				finish(s, fmt.Errorf("%w: %v", ErrStreamReset, f.ErrCode))
			}
		case *http2.GoAwayFrame:
			for _, s := range streams {
				if s.id > f.LastStreamID {
					finish(s, fmt.Errorf("%w: GOAWAY %v", ErrRefused, f.ErrCode))
				}
			}
		case *http2.SettingsFrame:
			if !f.IsAck() {
				c.writeLocked(c.fr.WriteSettingsAck)
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				data := f.Data
				c.writeLocked(func() error { return c.fr.WritePing(true, data) })
			}
		}
	}
}
