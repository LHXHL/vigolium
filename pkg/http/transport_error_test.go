package http

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	pkgerrors "github.com/pkg/errors"
)

// timeoutErr is a net.Error that reports a timeout, like the transport's
// "TLS handshake timeout" and "Client.Timeout exceeded" errors.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "net/http: TLS handshake timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func opErr(op string, err error) error {
	return &net.OpError{Op: op, Net: "tcp", Err: &os.SyscallError{Syscall: op, Err: err}}
}

func TestClassifyTransportError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},

		// Typed errors, as the standard library and dialer return them.
		{"dns nxdomain", &net.DNSError{Err: "no such host", Name: "nx.invalid", IsNotFound: true}, TransportErrDNS},
		{"refused", opErr("connect", syscall.ECONNREFUSED), TransportErrRefused},
		{"reset", opErr("read", syscall.ECONNRESET), TransportErrReset},
		{"broken pipe", opErr("write", syscall.EPIPE), TransportErrReset},
		{"eof", io.EOF, TransportErrReset},
		{"context deadline", context.DeadlineExceeded, TransportErrTimeout},
		{"os deadline", opErr("read", os.ErrDeadlineExceeded), TransportErrTimeout},
		{"net timeout", timeoutErr{}, TransportErrTimeout},
		{"tls record header", tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}, TransportErrTLS},
		{"tls unknown authority", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, TransportErrTLS},
		{"x509 hostname", x509.HostnameError{Certificate: &x509.Certificate{}, Host: "a.test"}, TransportErrTLS},

		// Wrapped the way the requester returns them: retryablehttp's
		// "giving up" wrapper (%w) and pkg/errors.Wrap.
		{"wrapped refused", fmt.Errorf("GET http://127.0.0.1:1 giving up after 2 attempts: %w",
			&wrapErr{err: opErr("connect", syscall.ECONNREFUSED)}), TransportErrRefused},
		{"pkg/errors wrapped dns", pkgerrors.Wrap(&net.DNSError{Err: "no such host", Name: "x"}, "could not do request"), TransportErrDNS},

		// Text-only errors, as fastdialer reports some failures.
		{"fastdialer resolve", errors.New("could not resolve host: nx.invalid"), TransportErrDNS},
		{"fastdialer no address", errors.New("no address found for host"), TransportErrDNS},
		{"fastdialer refused cause", errors.New("could not connect to any address found for host: dial tcp 127.0.0.1:1: connect: connection refused"), TransportErrRefused},
		{"fastdialer bare connect", errors.New("could not connect to any address found for host"), TransportErrRefused},
		{"fastdialer dial timeout", errors.New("could not connect to any address found for host: dial timeout"), TransportErrTimeout},
		{"text reset", errors.New("read tcp 1.2.3.4:5->6.7.8.9:443: read: connection reset by peer"), TransportErrReset},
		{"text tls handshake timeout", errors.New("net/http: TLS handshake timeout"), TransportErrTimeout},
		{"text x509", errors.New("tls: failed to verify certificate: x509: certificate signed by unknown authority"), TransportErrTLS},
		{"text eof", errors.New(`Get "http://a.test/": EOF`), TransportErrReset},
		{"cancelled", context.Canceled, TransportErrOther},
		{"other", errors.New("unsupported protocol scheme"), TransportErrOther},
	}
	for _, tc := range cases {
		if got := ClassifyTransportError(tc.err); got != tc.want {
			t.Errorf("%s: ClassifyTransportError(%v) = %q, want %q", tc.name, tc.err, got, tc.want)
		}
	}
}

// wrapErr mimics *url.Error's Unwrap so the wrapped-chain case exercises
// errors.As through more than one layer.
type wrapErr struct{ err error }

func (e *wrapErr) Error() string { return "Get \"http://127.0.0.1:1\": " + e.err.Error() }
func (e *wrapErr) Unwrap() error { return e.err }

// TestClassifyTransportErrorRealDial checks the classes against errors produced
// by real local dials, not hand-built ones.
func TestClassifyTransportErrorRealDial(t *testing.T) {
	t.Parallel()

	// A port that was listening and is now closed: connection refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	_, dialErr := net.DialTimeout("tcp", addr, 2*time.Second)
	if dialErr == nil {
		t.Skip("closed port unexpectedly accepted a connection")
	}
	if got := ClassifyTransportError(dialErr); got != TransportErrRefused {
		t.Errorf("closed port: class = %q (err %v), want refused", got, dialErr)
	}

	// TLS client against a plaintext listener that answers with HTTP: the
	// handshake fails with a record-header error.
	plain, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer plain.Close()
	go func() {
		c, err := plain.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		time.Sleep(200 * time.Millisecond)
		_ = c.Close()
	}()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", plain.Addr().String(),
		&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // local test listener
	if err == nil {
		_ = conn.Close()
		t.Fatal("TLS handshake against a plaintext listener succeeded")
	}
	if got := ClassifyTransportError(err); got != TransportErrTLS {
		t.Errorf("plaintext listener: class = %q (err %v), want tls", got, err)
	}
}
