// Package contracttest validates real machine output against the registered
// contract schemas, so a test that already captures a command's -j document
// (or an --events line, or an error envelope) can assert that the document
// matches what `vigolium schema` promises.
package contracttest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"sync"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/vigolium/vigolium/pkg/contract"
)

var (
	cacheMu sync.Mutex
	cache   = map[string]*jsonschema.Schema{}
)

// Validate asserts that doc, one -j document as printed (trailing newline
// allowed), matches the schema registered for command.
func Validate(t testing.TB, command string, doc []byte) {
	t.Helper()
	sch, err := compiled("command:"+command, func() (*contract.Schema, error) {
		return contract.CommandSchema(command)
	})
	if err != nil {
		t.Fatalf("contracttest: %v", err)
	}
	check(t, sch, "command "+command, doc)
}

// ValidateEvent asserts that line, one --events NDJSON line, matches the
// schema of its type.
func ValidateEvent(t testing.TB, line []byte) {
	t.Helper()
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(line, &head); err != nil {
		t.Fatalf("contracttest: event line is not JSON: %v\n%s", err, line)
	}
	sch, err := compiled("event:"+head.Type, func() (*contract.Schema, error) {
		return contract.EventSchema(head.Type)
	})
	if err != nil {
		t.Fatalf("contracttest: %v", err)
	}
	check(t, sch, "event "+head.Type, line)
}

// ValidateError asserts that doc matches the -j error envelope schema.
func ValidateError(t testing.TB, doc []byte) {
	t.Helper()
	sch, err := compiled("error", func() (*contract.Schema, error) {
		return contract.ErrorSchema(), nil
	})
	if err != nil {
		t.Fatalf("contracttest: %v", err)
	}
	check(t, sch, "error envelope", doc)
}

// Check reports whether doc matches the schema s, for a caller that builds
// its own schema (a drift test over a synthetic value).
func Check(s *contract.Schema, doc []byte) error {
	sch, err := compile("adhoc", s)
	if err != nil {
		return err
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(bytes.TrimSpace(doc)))
	if err != nil {
		return fmt.Errorf("document is not JSON: %w", err)
	}
	return sch.Validate(inst)
}

func check(t testing.TB, sch *jsonschema.Schema, what string, doc []byte) {
	t.Helper()
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(bytes.TrimSpace(doc)))
	if err != nil {
		t.Fatalf("contracttest: %s: document is not JSON: %v\n%s", what, err, doc)
	}
	if err := sch.Validate(inst); err != nil {
		t.Errorf("contracttest: %s does not match its schema (`vigolium schema`):\n%v\ndocument:\n%s", what, err, clip(doc))
	}
}

func compiled(key string, build func() (*contract.Schema, error)) (*jsonschema.Schema, error) {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if sch, ok := cache[key]; ok {
		return sch, nil
	}
	s, err := build()
	if err != nil {
		return nil, err
	}
	sch, err := compile(key, s)
	if err != nil {
		return nil, err
	}
	cache[key] = sch
	return sch, nil
}

// compile round-trips the reflected schema through JSON, the form a consumer
// sees, so the test validates exactly what `vigolium schema` prints.
func compile(key string, s *contract.Schema) (*jsonschema.Schema, error) {
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	loc := "mem://vigolium/" + url.PathEscape(key) + ".json"
	c := jsonschema.NewCompiler()
	if err := c.AddResource(loc, doc); err != nil {
		return nil, err
	}
	return c.Compile(loc)
}

func clip(doc []byte) []byte {
	const max = 4000
	if len(doc) <= max {
		return doc
	}
	return append(append([]byte(nil), doc[:max]...), "…"...)
}
