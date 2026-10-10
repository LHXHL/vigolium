// Package jsonstream holds the json.Decoder token helpers shared by the input
// formats that stream large JSON documents (HAR, Postman) one value at a time
// instead of unmarshalling them whole.
package jsonstream

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ReadKey consumes one token and returns it as an object key.
func ReadKey(dec *json.Decoder) (string, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", err
	}
	key, ok := tok.(string)
	if !ok {
		return "", fmt.Errorf("expected an object key, got %v", tok)
	}
	return key, nil
}

// ExpectDelim consumes one token and fails unless it is want.
func ExpectDelim(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != want {
		return fmt.Errorf("expected %q, got %v", want, tok)
	}
	return nil
}

// ExpectEOF rejects trailing data after the top-level value, as json.Unmarshal did.
func ExpectEOF(dec *json.Decoder) error {
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("unexpected data after the top-level value")
		}
		return err
	}
	return nil
}

// discard is a json.Unmarshaler that ignores its input. Decoding into it
// consumes one value through the decoder's reused buffer without building
// anything, which makes it the cheapest way to skip a subtree.
type discard struct{}

func (*discard) UnmarshalJSON([]byte) error { return nil }

// SkipValue consumes the next value whole without decoding it.
func SkipValue(dec *json.Decoder) error {
	return dec.Decode(&discard{})
}

// readBufferSize sizes the read buffer in front of the decoder. The decoder
// refills its own buffer only as far as the current value needs (a few KiB per
// entry), and a syscall per refill made streaming several times slower than
// reading the file whole.
const readBufferSize = 1 << 20

// SkipBOM buffers r and drops a leading UTF-8 byte-order mark, common on files
// exported from Windows tooling, which json.Unmarshal rejected.
func SkipBOM(r io.Reader) io.Reader {
	br := bufio.NewReaderSize(r, readBufferSize)
	if head, err := br.Peek(3); err == nil && string(head) == "\xef\xbb\xbf" {
		_, _ = br.Discard(3)
	}
	return br
}
