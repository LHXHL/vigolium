package har

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/vigolium/vigolium/pkg/input/formats/internal/jsonstream"
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
	dec := json.NewDecoder(jsonstream.SkipBOM(r))

	open, err := dec.Token()
	if err != nil {
		return err
	}
	if open == nil { // `null`, which json.Unmarshal accepted as an empty archive
		return jsonstream.ExpectEOF(dec)
	}
	if d, ok := open.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("expected a JSON object, got %v", open)
	}
	for dec.More() {
		key, err := jsonstream.ReadKey(dec)
		if err != nil {
			return err
		}
		if !strings.EqualFold(key, "log") {
			if err := jsonstream.SkipValue(dec); err != nil {
				return err
			}
			continue
		}
		cont, err := walkLog(dec, fn)
		if err != nil || !cont {
			return err
		}
	}
	if err := jsonstream.ExpectDelim(dec, '}'); err != nil {
		return err
	}
	return jsonstream.ExpectEOF(dec)
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
		key, err := jsonstream.ReadKey(dec)
		if err != nil {
			return false, err
		}
		if !strings.EqualFold(key, "entries") {
			if err := jsonstream.SkipValue(dec); err != nil {
				return false, err
			}
			continue
		}
		cont, err := walkArray(dec, fn)
		if err != nil || !cont {
			return false, err
		}
	}
	return true, jsonstream.ExpectDelim(dec, '}')
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
	return true, jsonstream.ExpectDelim(dec, ']')
}
