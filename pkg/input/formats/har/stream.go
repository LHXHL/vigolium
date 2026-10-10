package har

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// The HAR is walked with json.Decoder tokens rather than unmarshalled whole:
// a browser export of a long session runs to hundreds of megabytes, almost all
// of it in `log.entries[]`, and json.Unmarshal held the file bytes plus every
// decoded entry at once. Streaming keeps one entry in memory at a time, so a
// parse's peak heap is bounded by the largest entry, not the archive.
//
// Keys are matched case-insensitively, as json.Unmarshal matched struct fields.

// entryFunc handles one element of log.entries. The decoder is positioned at
// the element; the function must consume exactly that value. Returning false
// stops the walk without reading the rest of the input.
type entryFunc func(dec *json.Decoder, index int) (bool, error)

// walkEntries streams r to log.entries[] and calls fn for each element.
func walkEntries(r io.Reader, fn entryFunc) error {
	dec := json.NewDecoder(skipBOM(r))

	open, err := dec.Token()
	if err != nil {
		return err
	}
	if open == nil { // `null`, which json.Unmarshal accepted as an empty archive
		return expectEOF(dec)
	}
	if d, ok := open.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("expected a JSON object, got %v", open)
	}
	for dec.More() {
		key, err := readKey(dec)
		if err != nil {
			return err
		}
		if !strings.EqualFold(key, "log") {
			if err := skipValue(dec); err != nil {
				return err
			}
			continue
		}
		cont, err := walkLog(dec, fn)
		if err != nil || !cont {
			return err
		}
	}
	if err := expectDelim(dec, '}'); err != nil {
		return err
	}
	return expectEOF(dec)
}

// walkLog walks the `log` object, descending into `entries`.
func walkLog(dec *json.Decoder, fn entryFunc) (bool, error) {
	tok, err := dec.Token()
	if err != nil {
		return false, err
	}
	if tok == nil {
		return true, nil
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return false, fmt.Errorf("log: expected an object, got %v", tok)
	}
	for dec.More() {
		key, err := readKey(dec)
		if err != nil {
			return false, err
		}
		if !strings.EqualFold(key, "entries") {
			if err := skipValue(dec); err != nil {
				return false, err
			}
			continue
		}
		cont, err := walkArray(dec, fn)
		if err != nil || !cont {
			return false, err
		}
	}
	return true, expectDelim(dec, '}')
}

// walkArray calls fn for each element of the array the decoder is at.
func walkArray(dec *json.Decoder, fn entryFunc) (bool, error) {
	tok, err := dec.Token()
	if err != nil {
		return false, err
	}
	if tok == nil {
		return true, nil
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return false, fmt.Errorf("log.entries: expected an array, got %v", tok)
	}
	for i := 0; dec.More(); i++ {
		cont, err := fn(dec, i)
		if err != nil || !cont {
			return false, err
		}
	}
	return true, expectDelim(dec, ']')
}

func readKey(dec *json.Decoder) (string, error) {
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

func expectDelim(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != want {
		return fmt.Errorf("expected %q, got %v", want, tok)
	}
	return nil
}

// expectEOF rejects trailing data after the top-level value, as json.Unmarshal did.
func expectEOF(dec *json.Decoder) error {
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

func skipValue(dec *json.Decoder) error {
	return dec.Decode(&discard{})
}

// readBufferSize sizes the read buffer in front of the decoder. The decoder
// refills its own buffer only as far as the current value needs (a few KiB per
// entry), and a syscall per refill made streaming several times slower than
// reading the file whole.
const readBufferSize = 1 << 20

// skipBOM buffers r and drops a leading UTF-8 byte-order mark, common on files
// exported from Windows tooling, which json.Unmarshal rejected.
func skipBOM(r io.Reader) io.Reader {
	br := bufio.NewReaderSize(r, readBufferSize)
	if head, err := br.Peek(3); err == nil && string(head) == "\xef\xbb\xbf" {
		_, _ = br.Discard(3)
	}
	return br
}
