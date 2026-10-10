package postman

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/input/formats/internal/jsonstream"
)

// A collection is streamed with json.Decoder tokens rather than unmarshalled
// whole, so Parse holds one request at a time instead of the entire document.
//
// Streaming needs two passes because Postman writes the collection-level
// `auth` and `variable` blocks AFTER `item`, and a folder's `auth` after its
// own `item` array, yet both apply to the requests listed before them:
//
//  1. prescan walks the item tree decoding only the small blocks — variables,
//     collection auth, folder auth (keyed by the folder's index path) — and
//     counts requests. Count is this pass alone.
//  2. the parse pass walks the tree again, decoding one request at a time.
//
// Keys are matched case-insensitively, as json.Unmarshal matched struct fields.

// collectionScan is what the prescan learns about one collection object: the
// top-level document, or the `collection` member of a wrapped export.
type collectionScan struct {
	variables []variable
	auth      *auth
	// folderAuth holds the auth block of each folder that declares one, keyed
	// by itemPath. Request-level auth is decoded with its request instead.
	folderAuth map[string]*auth
	// requests counts items carrying a request, at every depth.
	requests int64
	// topItems is the number of entries in this collection's own `item` array.
	topItems int
}

// collectionPlan is the prescan result: the collection whose items are parsed.
type collectionPlan struct {
	// wrapped selects the {collection: {item: [...]}} shape, chosen exactly as
	// before: only when that inner collection has items.
	wrapped bool
	collectionScan
}

// itemPath names an item by its index path from the collection root
// ("0", "3/1/0", ...). The prescan and the parse pass number items the same
// way, nulls included, so the key identifies the same folder in both.
func itemPath(parent string, index int) string {
	if parent == "" {
		return strconv.Itoa(index)
	}
	return parent + "/" + strconv.Itoa(index)
}

// prescan reads a whole collection, keeping only variables, auth blocks and
// the request count.
func prescan(r io.Reader) (*collectionPlan, error) {
	dec := json.NewDecoder(jsonstream.SkipBOM(r))
	top := &collectionScan{folderAuth: map[string]*auth{}}
	var inner *collectionScan

	ok, err := openObject(dec)
	if err != nil {
		return nil, err
	}
	if ok {
		for dec.More() {
			key, err := jsonstream.ReadKey(dec)
			if err != nil {
				return nil, err
			}
			if strings.EqualFold(key, "collection") {
				scan := &collectionScan{folderAuth: map[string]*auth{}}
				present, err := scan.scanObject(dec)
				if err != nil {
					return nil, fmt.Errorf("collection: %w", err)
				}
				if present {
					inner = scan
				}
				continue
			}
			if err := top.scanMember(dec, key); err != nil {
				return nil, err
			}
		}
		if err := jsonstream.ExpectDelim(dec, '}'); err != nil {
			return nil, err
		}
	}
	if err := jsonstream.ExpectEOF(dec); err != nil {
		return nil, err
	}

	if inner != nil && inner.topItems > 0 {
		return &collectionPlan{wrapped: true, collectionScan: *inner}, nil
	}
	return &collectionPlan{collectionScan: *top}, nil
}

// scanObject scans a collection object; it reports false for `null`.
func (s *collectionScan) scanObject(dec *json.Decoder) (bool, error) {
	ok, err := openObject(dec)
	if err != nil || !ok {
		return false, err
	}
	for dec.More() {
		key, err := jsonstream.ReadKey(dec)
		if err != nil {
			return false, err
		}
		if err := s.scanMember(dec, key); err != nil {
			return false, err
		}
	}
	return true, jsonstream.ExpectDelim(dec, '}')
}

// scanMember consumes the value of one collection-object member.
func (s *collectionScan) scanMember(dec *json.Decoder, key string) error {
	switch {
	case strings.EqualFold(key, "item"):
		n, err := s.scanItems(dec, "")
		if err != nil {
			return fmt.Errorf("item: %w", err)
		}
		s.topItems = n
		return nil
	case strings.EqualFold(key, "variable"):
		s.variables = nil
		if err := dec.Decode(&s.variables); err != nil {
			return fmt.Errorf("variable: %w", err)
		}
		return nil
	case strings.EqualFold(key, "auth"):
		s.auth = nil
		if err := dec.Decode(&s.auth); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
		return nil
	default:
		return jsonstream.SkipValue(dec)
	}
}

// scanItems walks an `item` array and returns its length.
func (s *collectionScan) scanItems(dec *json.Decoder, parent string) (int, error) {
	ok, err := openArray(dec)
	if err != nil || !ok {
		return 0, err
	}
	n := 0
	for ; dec.More(); n++ {
		if err := s.scanItem(dec, itemPath(parent, n)); err != nil {
			return 0, err
		}
	}
	return n, jsonstream.ExpectDelim(dec, ']')
}

func (s *collectionScan) scanItem(dec *json.Decoder, path string) error {
	ok, err := openObject(dec)
	if err != nil || !ok {
		return err
	}
	var (
		itemAuth *auth
		isFolder bool
	)
	for dec.More() {
		key, err := jsonstream.ReadKey(dec)
		if err != nil {
			return err
		}
		switch {
		case strings.EqualFold(key, "item"):
			isFolder = true
			if _, err := s.scanItems(dec, path); err != nil {
				return err
			}
		case strings.EqualFold(key, "auth"):
			itemAuth = nil
			if err := dec.Decode(&itemAuth); err != nil {
				return fmt.Errorf("item %s auth: %w", path, err)
			}
		case strings.EqualFold(key, "request"):
			var probe nullProbe
			if err := dec.Decode(&probe); err != nil {
				return err
			}
			if !probe.null {
				s.requests++
			}
		default:
			if err := jsonstream.SkipValue(dec); err != nil {
				return err
			}
		}
	}
	if isFolder && itemAuth != nil {
		s.folderAuth[path] = itemAuth
	}
	return jsonstream.ExpectDelim(dec, '}')
}

// stream runs the parse pass: it walks to the planned collection's `item`
// array and hands each request to the walker.
func (w *walker) stream(r io.Reader, plan *collectionPlan) error {
	dec := json.NewDecoder(jsonstream.SkipBOM(r))
	ok, err := openObject(dec)
	if err != nil || !ok {
		return err
	}
	for dec.More() {
		key, err := jsonstream.ReadKey(dec)
		if err != nil {
			return err
		}
		var cont bool
		switch {
		case plan.wrapped && strings.EqualFold(key, "collection"):
			cont, err = w.streamCollection(dec, plan.auth)
		case !plan.wrapped && strings.EqualFold(key, "item"):
			cont, err = w.streamItems(dec, "", plan.auth)
		default:
			cont, err = true, jsonstream.SkipValue(dec)
		}
		if err != nil || !cont {
			return err
		}
	}
	return nil // the prescan already validated the rest of the document
}

func (w *walker) streamCollection(dec *json.Decoder, inherited *auth) (bool, error) {
	ok, err := openObject(dec)
	if err != nil || !ok {
		return true, err
	}
	for dec.More() {
		key, err := jsonstream.ReadKey(dec)
		if err != nil {
			return false, err
		}
		if !strings.EqualFold(key, "item") {
			if err := jsonstream.SkipValue(dec); err != nil {
				return false, err
			}
			continue
		}
		cont, err := w.streamItems(dec, "", inherited)
		if err != nil || !cont {
			return cont, err
		}
	}
	return true, jsonstream.ExpectDelim(dec, '}')
}

// streamItems processes an `item` array. It returns false once the callback
// declines a request, and every level propagates that so the WHOLE traversal
// stops: a `false` that only unwound the current folder let the parent carry
// on with its siblings, so ParseFileRecords(..., max) overshot its limit on
// nested collections.
func (w *walker) streamItems(dec *json.Decoder, parent string, inherited *auth) (bool, error) {
	ok, err := openArray(dec)
	if err != nil || !ok {
		return true, err
	}
	for i := 0; dec.More(); i++ {
		cont, err := w.streamItem(dec, itemPath(parent, i), inherited)
		if err != nil || !cont {
			return cont, err
		}
	}
	return true, jsonstream.ExpectDelim(dec, ']')
}

// streamItem processes one item: a folder's children first, then the item's
// own request (if any), matching the order the tree walk always used.
// inherited is the auth in effect for this level (collection or parent folder).
func (w *walker) streamItem(dec *json.Decoder, path string, inherited *auth) (bool, error) {
	ok, err := openObject(dec)
	if err != nil || !ok {
		return true, err
	}

	// A folder's own auth (including noauth) replaces what it inherited. The
	// prescan recorded it because it usually follows the folder's items.
	levelAuth := inherited
	if a := w.folderAuth[path]; a != nil {
		levelAuth = a
	}

	var (
		name     string
		req      *request
		itemAuth *auth
	)
	for dec.More() {
		key, err := jsonstream.ReadKey(dec)
		if err != nil {
			return false, err
		}
		switch {
		case strings.EqualFold(key, "item"):
			cont, err := w.streamItems(dec, path, levelAuth)
			if err != nil || !cont {
				return cont, err
			}
		case strings.EqualFold(key, "request"):
			if err := dec.Decode(&req); err != nil {
				return false, fmt.Errorf("item %q request: %w", name, err)
			}
		case strings.EqualFold(key, "auth"):
			itemAuth = nil
			if err := dec.Decode(&itemAuth); err != nil {
				return false, err
			}
		case strings.EqualFold(key, "name"):
			if err := dec.Decode(&name); err != nil {
				return false, err
			}
		default:
			if err := jsonstream.SkipValue(dec); err != nil {
				return false, err
			}
		}
	}
	if err := jsonstream.ExpectDelim(dec, '}'); err != nil {
		return false, err
	}

	if req == nil {
		return true, nil
	}
	if itemAuth != nil {
		levelAuth = itemAuth
	}
	reqAuth := levelAuth
	if req.Auth != nil {
		reqAuth = req.Auth
	}
	return w.emit(name, req, reqAuth), nil
}

// --- token helpers ---

// openObject consumes `{` and reports true, or consumes `null` and reports
// false (json.Unmarshal treated a null object as absent).
func openObject(dec *json.Decoder) (bool, error) {
	return openDelim(dec, '{')
}

// openArray is openObject for `[`.
func openArray(dec *json.Decoder) (bool, error) {
	return openDelim(dec, '[')
}

func openDelim(dec *json.Decoder, want json.Delim) (bool, error) {
	tok, err := dec.Token()
	if err != nil {
		return false, err
	}
	if tok == nil {
		return false, nil
	}
	if d, ok := tok.(json.Delim); !ok || d != want {
		return false, fmt.Errorf("expected %q, got %v", want, tok)
	}
	return true, nil
}

// nullProbe consumes one value and records whether it was `null`.
type nullProbe struct{ null bool }

func (p *nullProbe) UnmarshalJSON(b []byte) error {
	p.null = bytes.Equal(bytes.TrimSpace(b), []byte("null"))
	return nil
}
