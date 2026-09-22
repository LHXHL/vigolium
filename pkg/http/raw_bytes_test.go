package http

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// rawFullListener accepts one connection and captures everything the client
// writes — head AND body — so a test can assert the complete wire form of a
// request whose body framing is the thing under test.
func rawFullListener(t *testing.T) (addr string, wire <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ch := make(chan string, 1)
	go func() {
		defer func() { _ = ln.Close() }()
		conn, err := ln.Accept()
		if err != nil {
			ch <- ""
			return
		}
		defer func() { _ = conn.Close() }()
		// The deadline is a failure bound, not the normal path: reply as soon as
		// the head is complete. Waiting for the body to match its Content-Length
		// would hang forever on a TE.CL probe, which deliberately sends fewer
		// bytes than it claims — and the client is blocked on our response, so it
		// will not close first either.
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 8192)
		var b strings.Builder
		for {
			n, err := conn.Read(buf)
			b.Write(buf[:n])
			if err != nil || strings.Contains(b.String(), "\r\n\r\n") {
				break
			}
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		ch <- b.String()
	}()
	return ln.Addr().String(), ch
}

// countHeader reports how many times a header with the given name (case
// INSENSITIVE match) appears on the wire, and returns the values in order.
func countHeader(wire, name string) []string {
	var out []string
	head, _, _ := strings.Cut(wire, "\r\n\r\n")
	for _, line := range strings.Split(head, "\r\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), name) {
			out = append(out, strings.TrimSpace(v))
		}
	}
	return out
}

// sendVerbatim runs build(addr)'s bytes through the requester's RawBytes path to
// a throwaway listener and returns exactly what that listener received. build
// takes the address so the request can carry a matching Host header.
func sendVerbatim(t *testing.T, path string, build func(addr string) string) string {
	t.Helper()
	r := newTestRequester(t)
	addr, wire := rawFullListener(t)

	rr, err := httpmsg.GetRawRequestFromURL("http://" + addr + path)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, _, err := r.Execute(rr, Options{RawBytes: []byte(build(addr))})
	if resp != nil {
		resp.Close()
	}
	// A probe that under-sends its declared body may legitimately error; the
	// assertion is on what reached the wire, not on the reply.
	_ = err

	got := <-wire
	if got == "" {
		t.Fatal("listener captured nothing")
	}
	return got
}

// TestRawBytes_PreservesConflictingFraming is the regression test for the bug
// that made the request-smuggling module structurally incapable of a true
// positive: every probe it sent was silently normalized into an ordinary,
// well-formed POST before it reached the wire.
//
// net/http derives framing from req.ContentLength and req.TransferEncoding and
// ignores the headers of the same name, so a probe built as
// "Transfer-Encoding: chunked" + "Content-Length: 4" went out as a plain POST
// with Content-Length rewritten to the true body length and Transfer-Encoding
// dropped entirely. Probe and control were then byte-identical in framing,
// which is exactly why every reported anomaly had a control just as slow.
//
// Options.RawBytes must put the bytes on the wire untouched.
func TestRawBytes_PreservesConflictingFraming(t *testing.T) {
	// A CL.TE probe: Content-Length deliberately DISAGREES with the body length
	// (4 vs 11) and Transfer-Encoding is present. Both must survive.
	got := sendVerbatim(t, "/probe", func(addr string) string {
		return "POST /probe HTTP/1.1\r\n" +
			"Host: " + addr + "\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"Content-Length: 4\r\n" +
			"\r\n" +
			"1\r\nZ\r\nQ\r\n\r\n"
	})

	if cl := countHeader(got, "Content-Length"); len(cl) != 1 || cl[0] != "4" {
		t.Errorf("Content-Length on the wire = %v, want exactly [\"4\"] - a rewritten "+
			"or duplicated value means the CL/TE conflict was normalized away", cl)
	}
	if te := countHeader(got, "Transfer-Encoding"); len(te) != 1 || te[0] != "chunked" {
		t.Errorf("Transfer-Encoding on the wire = %v, want [\"chunked\"] - dropping it "+
			"turns the probe into an ordinary POST", te)
	}
	if !strings.HasSuffix(got, "1\r\nZ\r\nQ\r\n\r\n") {
		t.Errorf("body on the wire = %q, want the verbatim chunked-looking body", got)
	}
	// Nothing may be injected ahead of our bytes.
	if !strings.HasPrefix(got, "POST /probe HTTP/1.1\r\n") {
		t.Errorf("request line = %q, want the verbatim line", firstLine(got))
	}
}

// TestRawBytes_PreservesDuplicateAndOddCasedHeaders covers the TE.TE
// obfuscation probe, which needs TWO Transfer-Encoding headers differing only
// in case. An http.Header map cannot express that at all — Header.Add
// canonicalizes the key, collapsing "Transfer-encoding" into
// "Transfer-Encoding" — so only verbatim bytes carry it.
func TestRawBytes_PreservesDuplicateAndOddCasedHeaders(t *testing.T) {
	got := sendVerbatim(t, "/te-te", func(addr string) string {
		return "POST /te-te HTTP/1.1\r\n" +
			"Host: " + addr + "\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"Transfer-encoding: x\r\n" +
			"Content-Length: 4\r\n" +
			"\r\n" +
			"1\r\nZ\r\nQ\r\n\r\n"
	})

	te := countHeader(got, "Transfer-Encoding")
	if len(te) != 2 || te[0] != "chunked" || te[1] != "x" {
		t.Errorf("Transfer-Encoding headers on the wire = %v, want two in order "+
			"[chunked x] - a single header is not a TE.TE probe", te)
	}
	// Case must survive verbatim: the obfuscation IS the differing case.
	if !strings.Contains(got, "Transfer-encoding: x\r\n") {
		t.Errorf("wire lost the lower-cased second header:\n%q", got)
	}
}

// TestRawBytes_ShortBodyIsNotPadded proves a TE.CL probe reaches the server with
// FEWER body bytes than its Content-Length advertises. If the client padded or
// corrected the body to match, the back-end would never be left waiting and the
// probe could not produce the read-timeout that signals a desync.
func TestRawBytes_ShortBodyIsNotPadded(t *testing.T) {
	got := sendVerbatim(t, "/te-cl", func(addr string) string {
		return "POST /te-cl HTTP/1.1\r\n" +
			"Host: " + addr + "\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"Content-Length: 600\r\n" +
			"\r\n" +
			"0\r\n\r\nX"
	})

	if cl := countHeader(got, "Content-Length"); len(cl) != 1 || cl[0] != "600" {
		t.Errorf("Content-Length = %v, want [\"600\"] preserved even though only %d "+
			"body bytes follow", cl, len("0\r\n\r\nX"))
	}
	_, body, _ := strings.Cut(got, "\r\n\r\n")
	if body != "0\r\n\r\nX" {
		t.Errorf("body on the wire = %q, want %q unpadded", body, "0\r\n\r\nX")
	}
}

// TestRawBytes_ImpliesNoClustering guards the cache hazard: the cluster key is
// computed from the PARSED request, which for a RawBytes send no longer
// describes what goes out. Two probes differing only in framing would hash
// identically and be served each other's cached response — and for a framing
// attack that response difference is the entire measurement.
func TestRawBytes_ImpliesNoClustering(t *testing.T) {
	r := newTestRequester(t)
	if r.clusterer == nil {
		t.Skip("clustering disabled in this build")
	}

	addrA, wireA := rawFullListener(t)
	rrA, err := httpmsg.GetRawRequestFromURL("http://" + addrA + "/same")
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	rawA := "POST /same HTTP/1.1\r\nHost: " + addrA + "\r\nContent-Length: 1\r\n\r\nA"
	respA, _, err := r.Execute(rrA, Options{RawBytes: []byte(rawA)})
	if err != nil {
		t.Fatalf("Execute A: %v", err)
	}
	if respA != nil {
		respA.Close()
	}
	if got := <-wireA; !strings.HasSuffix(got, "\r\n\r\nA") {
		t.Fatalf("first send did not reach the wire: %q", got)
	}

	// Same parsed request shape, different verbatim bytes, sent immediately —
	// well inside the cluster cache TTL. It must still hit the network.
	addrB, wireB := rawFullListener(t)
	rrB, err := httpmsg.GetRawRequestFromURL("http://" + addrB + "/same")
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	rawB := "POST /same HTTP/1.1\r\nHost: " + addrB + "\r\nContent-Length: 1\r\n\r\nB"
	respB, _, err := r.Execute(rrB, Options{RawBytes: []byte(rawB)})
	if err != nil {
		t.Fatalf("Execute B: %v", err)
	}
	if respB != nil {
		respB.Close()
	}

	select {
	case got := <-wireB:
		if !strings.HasSuffix(got, "\r\n\r\nB") {
			t.Errorf("second send reached the wire as %q, want the verbatim B bytes", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("second RawBytes send never reached the wire — it was served from " +
			"the cluster cache, which must not happen for verbatim sends")
	}
}
