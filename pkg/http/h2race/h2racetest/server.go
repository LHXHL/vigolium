// Package h2racetest provides a raw HTTP/2 frame server for tests of the
// h2race package and the modules built on it. Unlike golang.org/x/net/http2's
// server it validates nothing: a handler sees every header field exactly as
// framed (including content-length / transfer-encoding that a conforming
// server would reject) and the body bytes received up to END_STREAM, so a
// test can play a downgrading front-end. Everything binds to 127.0.0.1.
package h2racetest

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// Stream is one request as the server received it.
type Stream struct {
	ID     uint32
	Fields []hpack.HeaderField // pseudo-headers first, as framed
	Body   []byte
	// HeadersAt and EndAt are when the HEADERS frame and the END_STREAM
	// frame were parsed.
	HeadersAt time.Time
	EndAt     time.Time
}

// Value returns the first field named name ("" when absent).
func (s *Stream) Value(name string) string {
	for _, f := range s.Fields {
		if f.Name == name {
			return f.Value
		}
	}
	return ""
}

// Reply is a handler's answer. A nil *Reply means never answer (a stall);
// Reset != 0 answers with RST_STREAM instead of a response.
type Reply struct {
	Status int
	Header [][2]string
	Body   string
	Reset  http2.ErrCode
}

// Handler answers a complete stream. It runs on its own goroutine.
type Handler func(s *Stream) *Reply

// Server is a TLS listener that speaks raw HTTP/2.
type Server struct {
	Host string
	Port int

	ln      net.Listener
	handler Handler

	mu      sync.Mutex
	streams []*Stream
	conns   []net.Conn
	wg      sync.WaitGroup
}

// NewTLS starts a server on 127.0.0.1 and stops it with t.Cleanup.
func NewTLS(t testing.TB, h Handler) *Server {
	t.Helper()
	// Borrow httptest's built-in certificate.
	ts := httptest.NewUnstartedServer(nil)
	ts.StartTLS()
	certs := ts.TLS.Certificates
	ts.Close()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: certs,
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("h2racetest: listen: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	s := &Server{Host: "127.0.0.1", Port: addr.Port, ln: ln, handler: h}
	s.wg.Add(1)
	go s.accept()
	t.Cleanup(s.Close)
	return s
}

// Addr is host:port.
func (s *Server) Addr() string { return net.JoinHostPort(s.Host, strconv.Itoa(s.Port)) }

// Close stops the listener, drops every connection and waits for the
// server's goroutines.
func (s *Server) Close() {
	_ = s.ln.Close()
	s.mu.Lock()
	for _, c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

// Streams returns every completed stream in END_STREAM order.
func (s *Server) Streams() []*Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*Stream(nil), s.streams...)
}

func (s *Server) accept() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns = append(s.conns, c)
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serve(c)
		}()
	}
}

type serverConn struct {
	fr  *http2.Framer
	bw  *bufio.Writer
	wmu sync.Mutex
	// enc carries HPACK dynamic-table state for the connection, so header
	// blocks are encoded under wmu in the order they are written.
	enc *hpack.Encoder
	hb  bytes.Buffer
}

func (sc *serverConn) write(fn func() error) {
	sc.wmu.Lock()
	defer sc.wmu.Unlock()
	if fn() == nil {
		_ = sc.bw.Flush()
	}
}

func (s *Server) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	br := bufio.NewReader(c)
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(br, preface); err != nil || string(preface) != http2.ClientPreface {
		return
	}
	sc := &serverConn{bw: bufio.NewWriter(c)}
	sc.enc = hpack.NewEncoder(&sc.hb)
	sc.fr = http2.NewFramer(sc.bw, br)
	sc.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	sc.write(func() error {
		return sc.fr.WriteSettings(http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100})
	})

	open := map[uint32]*Stream{}
	var handlers sync.WaitGroup
	defer handlers.Wait()
	for {
		f, err := sc.fr.ReadFrame()
		if err != nil {
			return
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				sc.write(sc.fr.WriteSettingsAck)
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				d := f.Data
				sc.write(func() error { return sc.fr.WritePing(true, d) })
			}
		case *http2.MetaHeadersFrame:
			st := &Stream{ID: f.StreamID, Fields: append([]hpack.HeaderField(nil), f.Fields...), HeadersAt: time.Now()}
			open[f.StreamID] = st
			if f.StreamEnded() {
				s.complete(sc, st, &handlers)
				delete(open, f.StreamID)
			}
		case *http2.DataFrame:
			st := open[f.StreamID]
			if st == nil {
				continue
			}
			st.Body = append(st.Body, f.Data()...)
			if n := uint32(len(f.Data())); n > 0 {
				sc.write(func() error { return sc.fr.WriteWindowUpdate(0, n) })
			}
			if f.StreamEnded() {
				s.complete(sc, st, &handlers)
				delete(open, f.StreamID)
			}
		}
	}
}

func (s *Server) complete(sc *serverConn, st *Stream, handlers *sync.WaitGroup) {
	st.EndAt = time.Now()
	s.mu.Lock()
	s.streams = append(s.streams, st)
	s.mu.Unlock()
	handlers.Add(1)
	go func() {
		defer handlers.Done()
		reply := s.handler(st)
		if reply == nil {
			return
		}
		sc.write(func() error {
			if reply.Reset != 0 {
				return sc.fr.WriteRSTStream(st.ID, reply.Reset)
			}
			sc.hb.Reset()
			_ = sc.enc.WriteField(hpack.HeaderField{Name: ":status", Value: strconv.Itoa(reply.Status)})
			for _, h := range reply.Header {
				_ = sc.enc.WriteField(hpack.HeaderField{Name: h[0], Value: h[1]})
			}
			if err := sc.fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID:      st.ID,
				BlockFragment: sc.hb.Bytes(),
				EndHeaders:    true,
				EndStream:     reply.Body == "",
			}); err != nil {
				return err
			}
			if reply.Body == "" {
				return nil
			}
			return sc.fr.WriteData(st.ID, true, []byte(reply.Body))
		})
	}()
}
