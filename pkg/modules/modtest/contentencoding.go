package modtest

import (
	"bytes"
	"compress/gzip"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
)

// BrotliDecoder decodes a Brotli document, reporting false when the bytes are
// not one. Pass nil to DecodeContentEncoding for the real Go decoder; a test
// that needs to simulate a decoder which accepts something the Go one refuses
// (an unpatched libbrotli, say) supplies its own.
type BrotliDecoder func([]byte) ([]byte, bool)

// DecodeContentEncoding undoes a Content-Encoding list on a request body,
// last-applied first, the way a server's body parser does. ok is false for any
// coding other than br/gzip, or for bytes that fail to decode.
//
// It is shared because a fake body parser is the only way to test a
// request-decoding module, and the codings it accepts have to agree with the
// encoded control streams the modules send — three copies of this had already
// drifted apart on whether an unknown coding is an error.
func DecodeContentEncoding(body []byte, encoding string, br BrotliDecoder) ([]byte, bool) {
	if br == nil {
		br = func(b []byte) ([]byte, bool) {
			out, err := io.ReadAll(brotli.NewReader(bytes.NewReader(b)))
			return out, err == nil
		}
	}
	if encoding == "" {
		return body, true
	}
	codings := strings.Split(encoding, ",")
	for i := len(codings) - 1; i >= 0; i-- {
		var out []byte
		var ok bool
		switch strings.TrimSpace(codings[i]) {
		case "br":
			out, ok = br(body)
		case "gzip":
			out, ok = gunzip(body)
		}
		if !ok {
			return nil, false
		}
		body = out
	}
	return body, true
}

func gunzip(body []byte) ([]byte, bool) {
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, false
	}
	out, err := io.ReadAll(zr)
	return out, err == nil
}
