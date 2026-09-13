package database

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// buildRawPair returns raw request/response bytes whose response body carries a
// recognizable marker, so a test can tell whose bytes a record ended up with.
func buildRawPair(marker string) (reqRaw, respRaw []byte) {
	req := "GET /" + marker + " HTTP/1.1\r\nHost: example.test\r\n\r\n"
	body := "body-" + marker
	resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s",
		len(body), body)
	return []byte(req), []byte(resp)
}

// TestFromHttpRequestResponseOwnsItsBytes is the regression test for records
// aliasing a caller's buffer. The executor builds every baseline response over a
// POOLED buffer and returns it to the pool when the item is done — while the
// record may still be queued in the writer or waiting for the fsexport mirror.
// Overwriting the source buffer here simulates exactly that reuse.
func TestFromHttpRequestResponseOwnsItsBytes(t *testing.T) {
	reqRaw, respRaw := buildRawPair("first")

	// Caller-owned (here: "pooled") buffers, as the executor would supply them.
	reqBuf := make([]byte, len(reqRaw))
	copy(reqBuf, reqRaw)
	respBuf := make([]byte, len(respRaw))
	copy(respBuf, respRaw)

	req, err := httpmsg.ParseRawRequest(string(reqBuf))
	if err != nil {
		t.Fatalf("ParseRawRequest: %v", err)
	}
	req = req.WithService(httpmsg.NewServiceSecure("example.test", 80, false))
	rr := req.WithResponse(httpmsg.NewHttpResponse(respBuf))

	record := &HTTPRecord{}
	if err := record.FromHttpRequestResponse(rr); err != nil {
		t.Fatalf("FromHttpRequestResponse: %v", err)
	}

	gotReq := append([]byte(nil), record.RawRequest...)
	gotResp := append([]byte(nil), record.RawResponse...)

	// The pool hands both buffers to the next item, which overwrites them.
	for i := range reqBuf {
		reqBuf[i] = 'X'
	}
	for i := range respBuf {
		respBuf[i] = 'X'
	}

	if !bytes.Equal(record.RawRequest, gotReq) {
		t.Errorf("RawRequest changed when the source buffer was reused:\n got %q\nwant %q",
			record.RawRequest, gotReq)
	}
	if !bytes.Equal(record.RawResponse, gotResp) {
		t.Errorf("RawResponse changed when the source buffer was reused:\n got %q\nwant %q",
			record.RawResponse, gotResp)
	}
	if !bytes.Contains(record.RawResponse, []byte("body-first")) {
		t.Errorf("RawResponse lost its own body: %q", record.RawResponse)
	}
}
