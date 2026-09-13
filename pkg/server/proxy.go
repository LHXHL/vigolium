package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/server/mitm"
	"github.com/vigolium/vigolium/pkg/storagesig"
	"go.uber.org/zap"
)

// newIngestProxy creates a transparent HTTP forward proxy that records
// request/response pairs into the database.
//
// When mitmCA is non-nil, HTTPS CONNECT tunnels are intercepted: the proxy
// terminates TLS with a leaf certificate minted by mitmCA, records the
// decrypted request/response, and re-originates to the real target. When nil,
// CONNECT tunnels are passed through unmodified (HTTPS traffic is not recorded).
// upstreamInsecure skips verification of the real server's certificate during
// re-origination (only meaningful when mitmCA is set).
func newIngestProxy(addr string, db *database.DB, repo *database.Repository, rw *database.RecordWriter, settings *config.Settings, getScopeMatcher func() *config.ScopeMatcher, mitmCA *mitm.CA, upstreamInsecure bool) *http.Server {
	handler := &proxyHandler{
		db:              db,
		repo:            repo,
		recordWriter:    rw,
		settings:        settings,
		transport:       &http.Transport{},
		getScopeMatcher: getScopeMatcher,
		mitmCA:          mitmCA,
	}

	if mitmCA != nil {
		handler.upstreamTransport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				// #nosec G402 — verification is on by default; only skipped when
				// the operator explicitly passes --proxy-insecure.
				InsecureSkipVerify: upstreamInsecure,
				NextProtos:         []string{"http/1.1"}, // keep upstream HTTP/1.1
			},
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		}
	}

	return &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
}

type proxyHandler struct {
	db              *database.DB
	repo            *database.Repository
	recordWriter    *database.RecordWriter
	settings        *config.Settings
	transport       *http.Transport
	getScopeMatcher func() *config.ScopeMatcher

	// mitmCA, when non-nil, enables TLS interception of CONNECT tunnels.
	mitmCA *mitm.CA
	// upstreamTransport re-originates intercepted requests to the real target.
	// Non-nil only when mitmCA is set.
	upstreamTransport *http.Transport
}

func (p *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

// defaultMaxProxyBodySize is the maximum body size (request or response) that
// the proxy will buffer for recording. Larger bodies are still forwarded to
// the client in full but skipped for database recording to prevent OOM.
const defaultMaxProxyBodySize = 10 * 1024 * 1024 // 10 MB

// captureBuffer records up to limit bytes of a stream it is teed onto while
// counting the total bytes seen. It lets the proxy forward a body to the client
// in full yet retain only a bounded copy for recording — the recording limit must
// never truncate the forwarded traffic. Write never returns short or errors, so
// the io.Copy/TeeReader driving the forward is never throttled by the capture.
type captureBuffer struct {
	buf   bytes.Buffer
	limit int
	total int64
}

func (c *captureBuffer) Write(p []byte) (int, error) {
	c.total += int64(len(p))
	if rem := c.limit - c.buf.Len(); rem > 0 {
		if len(p) > rem {
			c.buf.Write(p[:rem])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

// Bytes returns the captured prefix (valid only when !truncated for recording).
func (c *captureBuffer) Bytes() []byte { return c.buf.Bytes() }

// truncated reports whether the stream exceeded the capture limit, meaning the
// captured copy is a prefix and must not be recorded as a complete message.
func (c *captureBuffer) truncated() bool { return c.total > int64(c.limit) }

// responseHasNoBody reports whether resp carries no message body per HTTP rules,
// so it must be written with its original framing (no chunked body) instead of
// being streamed.
func responseHasNoBody(resp *http.Response, req *http.Request) bool {
	if req != nil && req.Method == http.MethodHead {
		return true
	}
	return resp.StatusCode == http.StatusNoContent ||
		resp.StatusCode == http.StatusNotModified ||
		(resp.StatusCode >= 100 && resp.StatusCode < 200)
}

// handleHTTP forwards plain HTTP requests and records the transaction. The
// recording size limit only bounds the copy kept for the database — the full
// request and response are always forwarded to the client untouched.
func (p *proxyHandler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	const maxBody = defaultMaxProxyBodySize

	// Tee the request body: RoundTrip forwards the FULL body upstream while we
	// retain a bounded copy for recording. A body larger than the limit is still
	// forwarded intact — only the recorded copy is capped.
	var reqCap *captureBuffer
	if r.Body != nil {
		reqCap = &captureBuffer{limit: maxBody}
		r.Body = io.NopCloser(io.TeeReader(r.Body, reqCap))
	}

	// Ensure absolute URL for proxy
	if !r.URL.IsAbs() {
		http.Error(w, "absolute URL required for proxy", http.StatusBadRequest)
		return
	}

	// Forward the request
	upstreamStart := time.Now()
	resp, err := p.transport.RoundTrip(r)
	if err != nil {
		zap.L().Debug("Proxy forward failed", zap.String("url", r.URL.String()), zap.Error(err))
		http.Error(w, "proxy forward failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// Stream the full response body to the client, teeing a bounded copy for
	// recording. Copying the header map (as adjusted by the transport) preserves
	// the upstream framing, so streaming forwards the body byte-for-byte.
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Fast path for a response the transport already knows is oversize: forward it
	// straight through without teeing into a capture buffer we'd only fill to the
	// limit and then discard (recording is skipped for truncated bodies anyway).
	if resp.ContentLength > maxBody {
		_, _ = io.Copy(w, resp.Body)
		return
	}

	respCap := &captureBuffer{limit: maxBody}
	if _, err := io.Copy(w, io.TeeReader(resp.Body, respCap)); err != nil {
		// Client hung up or upstream errored mid-stream; the partial body already
		// reached the client, so there's nothing faithful left to record.
		zap.L().Debug("Proxy: response stream to client interrupted",
			zap.String("url", r.URL.String()), zap.Error(err))
		return
	}

	// A body larger than the capture limit was forwarded in full but is too large
	// to record faithfully; skip recording rather than store a truncated body.
	if respCap.truncated() || (reqCap != nil && reqCap.truncated()) {
		zap.L().Debug("Proxy: body exceeded capture limit, forwarded but not recorded",
			zap.String("url", r.URL.String()))
		return
	}

	var reqBody []byte
	if reqCap != nil {
		reqBody = reqCap.Bytes()
	}
	// Record transaction in background so the client is off the DB-write path.
	// The duration is measured to the END of the client stream, not to
	// RoundTrip's return: RoundTrip returns once the headers are in, and the
	// body then arrives while we tee it. Stopping at the header would report a
	// TTFB as if it were the whole transaction.
	go p.recordTransaction(r, reqBody, resp, respCap.Bytes(), time.Since(upstreamStart))
}

// handleConnect handles HTTPS CONNECT. With a MITM CA configured it intercepts
// and records the TLS traffic; otherwise it tunnels through without recording.
func (p *proxyHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	if p.mitmCA != nil {
		p.interceptConnect(w, r)
		return
	}
	p.tunnelConnect(w, r)
}

// tunnelConnect blindly pipes a CONNECT tunnel between client and target. The
// proxy never sees the plaintext, so nothing is recorded.
func (p *proxyHandler) tunnelConnect(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, "cannot reach destination", http.StatusBadGateway)
		return
	}

	// Hijack BEFORE acknowledging so we write the CONNECT response onto the raw
	// connection ourselves (calling WriteHeader first leaves the server in
	// control of the framing, which corrupts the tunnel).
	clientConn, err := hijackConn(w)
	if err != nil {
		_ = destConn.Close()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = destConn.Close()
		_ = clientConn.Close()
		return
	}

	go func() {
		defer func() { _ = destConn.Close() }()
		defer func() { _ = clientConn.Close() }()
		_, _ = io.Copy(destConn, clientConn)
	}()
	go func() {
		defer func() { _ = destConn.Close() }()
		defer func() { _ = clientConn.Close() }()
		_, _ = io.Copy(clientConn, destConn)
	}()
}

// interceptConnect terminates the client's TLS using a minted leaf certificate,
// then serves the decrypted requests over the tunnel — recording each and
// re-originating to the real target.
func (p *proxyHandler) interceptConnect(w http.ResponseWriter, r *http.Request) {
	hostPort := r.Host // authority form, e.g. "example.com:443"

	clientConn, err := hijackConn(w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer func() { _ = clientConn.Close() }()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	tlsConn := tls.Server(clientConn, p.mitmCA.TLSConfigForHost(hostPort))
	if err := tlsConn.Handshake(); err != nil {
		zap.L().Debug("Proxy MITM: client TLS handshake failed",
			zap.String("host", hostPort), zap.Error(err))
		return
	}
	defer func() { _ = tlsConn.Close() }()

	p.serveDecrypted(tlsConn, hostPort)
}

// serveDecrypted reads plaintext HTTP requests off an intercepted TLS
// connection (honoring keep-alive), forwards each to the real target, records
// the transaction, and writes the response back to the client.
func (p *proxyHandler) serveDecrypted(tlsConn *tls.Conn, hostPort string) {
	host := hostPort
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		host = h
	}

	br := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				zap.L().Debug("Proxy MITM: read request", zap.String("host", host), zap.Error(err))
			}
			return
		}

		// Tee the request body so RoundTrip forwards it in full upstream while we
		// keep a bounded copy for recording. A body larger than the limit is still
		// forwarded intact — only the recorded copy is capped.
		var reqCap *captureBuffer
		if req.Body != nil {
			reqCap = &captureBuffer{limit: defaultMaxProxyBodySize}
			req.Body = io.NopCloser(io.TeeReader(req.Body, reqCap))
		}

		// Turn the origin-form request into an absolute one for the client
		// transport and strip fields that don't belong on an outbound request.
		req.URL.Scheme = "https"
		req.URL.Host = req.Host
		if req.URL.Host == "" {
			req.URL.Host = hostPort
			req.Host = host
		}
		req.RequestURI = "" // must be empty on a client request
		req.Header.Del("Proxy-Connection")
		// Let the transport negotiate (and transparently decompress) encoding so
		// recorded + returned bodies are plaintext — far more useful to the
		// scanner than gzipped bytes.
		req.Header.Del("Accept-Encoding")

		upstreamStart := time.Now()
		resp, err := p.upstreamTransport.RoundTrip(req)
		if err != nil {
			zap.L().Debug("Proxy MITM: upstream round-trip failed",
				zap.String("url", req.URL.String()), zap.Error(err))
			writeBadGateway(tlsConn, err)
			return
		}

		keepAlive := !resp.Close && !req.Close
		respCap := &captureBuffer{limit: defaultMaxProxyBodySize}

		// Write the response back to the client first, then record. Recording
		// after the write keeps the client off the DB-write latency path.
		if responseHasNoBody(resp, req) {
			// No message body (204/304/HEAD): write with original framing.
			_ = resp.Body.Close()
			if err := writeIntercepted(tlsConn, resp, nil); err != nil {
				return
			}
		} else {
			// Stream the FULL body to the client (chunked framing) while teeing a
			// bounded copy for recording, so a body larger than the capture limit
			// is forwarded intact instead of truncated.
			streamErr := streamIntercepted(tlsConn, resp, respCap, keepAlive)
			_ = resp.Body.Close()
			if streamErr != nil {
				zap.L().Debug("Proxy MITM: response stream failed",
					zap.String("url", req.URL.String()), zap.Error(streamErr))
				return
			}
		}

		// Record only when neither side exceeded the capture limit, so a truncated
		// prefix is never stored as if it were the complete message.
		if !respCap.truncated() && (reqCap == nil || !reqCap.truncated()) {
			var reqBody []byte
			if reqCap != nil {
				reqBody = reqCap.Bytes()
			}
			p.recordTransaction(req, reqBody, resp, respCap.Bytes(), time.Since(upstreamStart))
		}

		if !keepAlive {
			return
		}
	}
}

// hijackConn takes over the underlying TCP connection from the ResponseWriter.
func hijackConn(w http.ResponseWriter) (net.Conn, error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("hijacking not supported")
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return nil, fmt.Errorf("hijack connection: %w", err)
	}
	return conn, nil
}

// writeIntercepted serializes resp (with the already-buffered body) back to the
// client over the intercepted TLS connection.
func writeIntercepted(w io.Writer, resp *http.Response, body []byte) error {
	// The transport may have decompressed the body, so the upstream
	// Content-Length / Transfer-Encoding no longer apply. Drop them and let
	// resp.Write recompute Content-Length from the buffered body.
	resp.Header.Del("Content-Length")
	resp.Header.Del("Transfer-Encoding")
	resp.TransferEncoding = nil
	resp.ContentLength = int64(len(body))
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp.Write(w)
}

// streamIntercepted writes resp's status line and headers to the client, then
// streams the FULL body with chunked transfer-encoding while teeing a bounded
// copy into capture. Unlike writeIntercepted (which buffers the whole body), this
// never truncates the forwarded body when it exceeds the recording limit. It does
// NOT mutate resp.Header, so a later recordTransaction records the true upstream
// headers rather than the proxy's re-framing.
func streamIntercepted(w io.Writer, resp *http.Response, capture *captureBuffer, keepAlive bool) error {
	var head bytes.Buffer
	fmt.Fprintf(&head, "%s %s\r\n", resp.Proto, resp.Status)
	for k, vv := range resp.Header {
		// Drop hop-by-hop / framing headers we recompute; Content-Encoding is
		// preserved so the client can still decode the forwarded (undecoded) body.
		switch k {
		case "Content-Length", "Transfer-Encoding", "Connection":
			continue
		}
		for _, v := range vv {
			fmt.Fprintf(&head, "%s: %s\r\n", k, v)
		}
	}
	head.WriteString("Transfer-Encoding: chunked\r\n")
	if keepAlive {
		head.WriteString("Connection: keep-alive\r\n")
	} else {
		head.WriteString("Connection: close\r\n")
	}
	head.WriteString("\r\n")
	if _, err := w.Write(head.Bytes()); err != nil {
		return err
	}

	cw := httputil.NewChunkedWriter(w)
	if _, err := io.Copy(cw, io.TeeReader(resp.Body, capture)); err != nil {
		_ = cw.Close()
		return err
	}
	if err := cw.Close(); err != nil {
		return err
	}
	// Terminate the chunked stream (Close writes the 0-length chunk; the caller
	// must send the final CRLF ending the empty trailer section).
	_, err := w.Write([]byte("\r\n"))
	return err
}

// writeBadGateway emits a minimal 502 onto a raw connection.
func writeBadGateway(w io.Writer, cause error) {
	body := "proxy forward failed: " + cause.Error()
	_, _ = fmt.Fprintf(w,
		"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body)
}

// recordTransaction builds an HttpRequestResponse and saves it to the database.
func (p *proxyHandler) recordTransaction(r *http.Request, reqBody []byte, resp *http.Response, respBody []byte, elapsed time.Duration) {
	if p.repo == nil {
		return
	}

	// Build raw HTTP request string
	var rawReq strings.Builder
	fmt.Fprintf(&rawReq, "%s %s %s\r\n", r.Method, r.URL.RequestURI(), r.Proto)
	fmt.Fprintf(&rawReq, "Host: %s\r\n", r.Host)
	for k, vv := range r.Header {
		for _, v := range vv {
			fmt.Fprintf(&rawReq, "%s: %s\r\n", k, v)
		}
	}
	rawReq.WriteString("\r\n")
	if len(reqBody) > 0 {
		rawReq.Write(reqBody)
	}

	rr, err := httpmsg.ParseRawRequestWithURL(rawReq.String(), r.URL.String())
	if err != nil {
		zap.L().Debug("Proxy: failed to parse recorded request", zap.Error(err))
		return
	}

	// Build raw HTTP response
	var rawResp strings.Builder
	fmt.Fprintf(&rawResp, "%s %s\r\n", resp.Proto, resp.Status)
	for k, vv := range resp.Header {
		for _, v := range vv {
			fmt.Fprintf(&rawResp, "%s: %s\r\n", k, v)
		}
	}
	rawResp.WriteString("\r\n")
	if len(respBody) > 0 {
		rawResp.Write(respBody)
	}

	httpResp := httpmsg.NewHttpResponseWithDuration([]byte(rawResp.String()), elapsed)
	if httpResp != nil {
		rr = rr.WithResponse(httpResp)
	}

	if p.settings != nil {
		matcher := p.getScopeMatcher()
		if matcher != nil {
			if matcher.IsStaticFile(rr.Request().Path()) {
				var hg storagesig.HeaderGetter
				if rr.HasResponse() && rr.Response() != nil {
					hg = rr.Response()
				}
				if !storagesig.KeepStaticAsMeta(rr.Request().Path(), hg) {
					return
				}
				if rr.Response() != nil {
					rr.Response().TruncateBody(0) // metadata-only: keep headers, drop body
				}
			}
			if p.settings.Scope.AppliedOnIngest && !matcher.InScope(buildScopeMatchInput(rr)) {
				return
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if p.recordWriter != nil {
		if _, err := p.recordWriter.Write(ctx, rr, "ingest-proxy", database.DefaultProjectUUID); err != nil {
			zap.L().Debug("Proxy: failed to save record", zap.Error(err))
		}
	} else if _, err := p.repo.SaveRecord(ctx, rr, "ingest-proxy", database.DefaultProjectUUID); err != nil {
		zap.L().Debug("Proxy: failed to save record", zap.Error(err))
	}
}
