package vigtool

import "testing"

func TestArgsString(t *testing.T) {
	cases := map[string]string{
		"missing":       "",
		"empty":         "",
		"whitespace":    "",
		"trimmed":       "value",
		"already-clean": "exact",
	}
	args := map[string]any{
		"empty":         "",
		"whitespace":    "   ",
		"trimmed":       "  value  ",
		"already-clean": "exact",
		"non-string":    123,
	}
	for key, want := range cases {
		if got := argsString(args, key); got != want {
			t.Errorf("argsString(%q) = %q, want %q", key, got, want)
		}
	}
	if got := argsString(args, "non-string"); got != "" {
		t.Errorf("argsString on non-string should return empty, got %q", got)
	}
}

func TestArgsStringArrayConcrete(t *testing.T) {
	args := map[string]any{"k": []string{"a", "", "  b  ", "c"}}
	got := argsStringArray(args, "k")
	want := []string{"a", "b", "c"}
	if !equalStrings(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestArgsStringArrayFromAny(t *testing.T) {
	// JSON-decoded arrays surface as []any, which is the common path.
	args := map[string]any{"k": []any{"x", 42, "  y  ", nil, "z"}}
	got := argsStringArray(args, "k")
	want := []string{"x", "y", "z"}
	if !equalStrings(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestArgsStringArrayMissing(t *testing.T) {
	args := map[string]any{}
	if got := argsStringArray(args, "missing"); got != nil {
		t.Errorf("missing key should return nil, got %v", got)
	}
}

func TestArgsBool(t *testing.T) {
	args := map[string]any{"yes": true, "no": false, "bad": "true"}
	if !argsBool(args, "yes") {
		t.Error("yes should be true")
	}
	if argsBool(args, "no") {
		t.Error("no should be false")
	}
	if argsBool(args, "missing") {
		t.Error("missing should be false")
	}
	if argsBool(args, "bad") {
		t.Error("string 'true' should not be coerced to bool")
	}
}

func TestArgsInt(t *testing.T) {
	args := map[string]any{
		"float":  float64(42),
		"int":    int(7),
		"int64":  int64(99),
		"string": "12",
		"miss":   nil,
	}
	if got := argsInt(args, "float"); got != 42 {
		t.Errorf("float -> %d, want 42", got)
	}
	if got := argsInt(args, "int"); got != 7 {
		t.Errorf("int -> %d, want 7", got)
	}
	if got := argsInt(args, "int64"); got != 99 {
		t.Errorf("int64 -> %d, want 99", got)
	}
	if got := argsInt(args, "string"); got != 0 {
		t.Errorf("string args should not coerce, got %d", got)
	}
	if got := argsInt(args, "missing"); got != 0 {
		t.Errorf("missing key should be 0, got %d", got)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestArgsArraysAcceptScalars pins the shapes a model actually sends for an
// array parameter. A bare string used to return nil, which surfaced as
// "'targets' is required and must be non-empty" for an argument that was
// right there in the call.
func TestArgsArraysAcceptScalars(t *testing.T) {
	if got := argsStringArray(map[string]any{"targets": "https://example.test"}, "targets"); len(got) != 1 || got[0] != "https://example.test" {
		t.Errorf("bare string: got %v, want one-element list", got)
	}
	if got := argsStringArray(map[string]any{"targets": "  "}, "targets"); got != nil {
		t.Errorf("blank string should stay empty, got %v", got)
	}
	if got := argsIntArray(map[string]any{"status": float64(200)}, "status"); len(got) != 1 || got[0] != 200 {
		t.Errorf("bare number: got %v, want [200]", got)
	}
	if got := argsIntArray(map[string]any{"status": "404"}, "status"); len(got) != 1 || got[0] != 404 {
		t.Errorf("numeric string: got %v, want [404]", got)
	}
	if got := argsIntArray(map[string]any{"status": []any{"200", float64(404)}}, "status"); len(got) != 2 || got[0] != 200 || got[1] != 404 {
		t.Errorf("mixed array: got %v, want [200 404]", got)
	}
	// Unchanged for the canonical shapes.
	if got := argsStringArray(map[string]any{"t": []any{"a", "b"}}, "t"); len(got) != 2 {
		t.Errorf("[]any regression: %v", got)
	}
}
