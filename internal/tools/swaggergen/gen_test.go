package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// repoFile reads a path relative to the repository root.
func repoFile(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return b
}

// TestCheckedInSpecIsGenerated: the canonical spec is a fixed point of the
// generator and the embedded copy matches it byte for byte, i.e. nobody edited
// a schema by hand or changed types.go without running `make swagger`.
func TestCheckedInSpecIsGenerated(t *testing.T) {
	canonical := repoFile(t, canonicalPath)
	out, err := generate(canonical)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !bytes.Equal(out, canonical) {
		t.Fatalf("%s is stale: run `make swagger` and commit the result", canonicalPath)
	}
	if !bytes.Equal(repoFile(t, embeddedPath), canonical) {
		t.Fatalf("%s differs from %s: run `make swagger`", embeddedPath, canonicalPath)
	}
}

// TestMergeKeepsProse: hand-written annotations survive regeneration for
// properties that still exist, typed annotations are dropped when the type
// changed, and stale required entries are pruned.
func TestMergeKeepsProse(t *testing.T) {
	gen := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name":    map[string]any{"type": "string"},
			"timeout": map[string]any{"type": "string"},
			"data":    map[string]any{},
		},
	}
	old := map[string]any{
		"type":        "object",
		"description": "a thing",
		"required":    []any{"name", "gone"},
		"properties": map[string]any{
			"name":    map[string]any{"type": "string", "description": "the name", "example": "x"},
			"timeout": map[string]any{"type": "integer", "description": "seconds", "example": 30},
			"data":    map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
			"gone":    map[string]any{"type": "string"},
		},
	}
	got := mergeSchema(gen, old)
	props := got["properties"].(map[string]any)
	if got["description"] != "a thing" {
		t.Errorf("schema description lost: %v", got["description"])
	}
	if req := got["required"].([]any); len(req) != 1 || req[0] != "name" {
		t.Errorf("required = %v, want [name]", req)
	}
	name := props["name"].(map[string]any)
	if name["description"] != "the name" || name["example"] != "x" {
		t.Errorf("name prose lost: %v", name)
	}
	timeout := props["timeout"].(map[string]any)
	if timeout["type"] != "string" || timeout["description"] != "seconds" {
		t.Errorf("timeout = %v, want generated type with carried description", timeout)
	}
	if _, ok := timeout["example"]; ok {
		t.Errorf("timeout kept an example of the old type: %v", timeout)
	}
	if props["data"].(map[string]any)["type"] != "array" {
		t.Errorf("untyped generated property should keep the hand-written schema: %v", props["data"])
	}
	if _, ok := props["gone"]; ok {
		t.Errorf("removed property resurrected")
	}
}
