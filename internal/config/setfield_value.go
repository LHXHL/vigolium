package config

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// This file holds SetField's parsing of list and map values. Before it, every
// list value was split on commas, so `config set scope.host.include
// '["a.example","b.example"]'` stored the two patterns `["a.example"` and
// `"b.example"]` — JSON residue that matched nothing and silently emptied the
// scope.

func isListType(t reflect.Type) bool {
	return t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array)
}

func isContainerType(t reflect.Type) bool {
	return isListType(t) || (t != nil && t.Kind() == reflect.Map)
}

func isContainerValue(v any) bool {
	switch v.(type) {
	case []any, map[string]any:
		return true
	}
	return false
}

// looksStructured reports whether value is written as a YAML/JSON flow list or
// map rather than the comma form.
func looksStructured(value string) bool {
	v := strings.TrimSpace(value)
	return strings.HasPrefix(v, "[") || strings.HasPrefix(v, "{")
}

// parseContainerValue turns the command-line value for a list or map field
// into the generic form the raw settings map holds. declared may be nil when
// the key could not be resolved against the struct (the existing value's shape
// then decides).
func parseContainerValue(key, value string, declared reflect.Type, existing any) (any, error) {
	if declared == nil {
		switch existing.(type) {
		case map[string]any:
			declared = reflect.TypeOf(map[string]any{})
		default:
			declared = reflect.TypeOf([]any{})
		}
	}
	if looksStructured(value) {
		v, err := parseStructuredValue(value, declared)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrInvalidValue, key, err)
		}
		return v, nil
	}
	if !isListType(declared) {
		return nil, fmt.Errorf("%w: %s expects %s; pass a JSON or YAML object, e.g. '{\"name\":\"value\"}'",
			ErrInvalidValue, key, describeType(declared))
	}
	if strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("%w: %s: empty value; use `%s.clear` or '[]' to empty the list",
			ErrInvalidValue, key, key)
	}
	parts := strings.Split(value, ",")
	out := make([]any, 0, len(parts))
	for i, p := range parts {
		elem, err := parseCommaElement(strings.TrimSpace(p), declared.Elem())
		if err != nil {
			return nil, fmt.Errorf("%w: %s: element %d: %v", ErrInvalidValue, key, i, err)
		}
		out = append(out, elem)
	}
	return out, nil
}

// parseListAddition parses the value of a `<list>.add` op: either one element,
// or a JSON/YAML list whose elements are all appended.
func parseListAddition(listPath, value string, declared reflect.Type) ([]any, error) {
	if !isListType(declared) {
		declared = reflect.TypeOf([]any{})
	}
	if strings.HasPrefix(strings.TrimSpace(value), "[") {
		v, err := parseStructuredValue(value, declared)
		if err != nil {
			return nil, fmt.Errorf("%w: %s.add: %v", ErrInvalidValue, listPath, err)
		}
		items, _ := v.([]any)
		return items, nil
	}
	elem, err := parseCommaElement(strings.TrimSpace(value), declared.Elem())
	if err != nil {
		return nil, fmt.Errorf("%w: %s.add: %v", ErrInvalidValue, listPath, err)
	}
	return []any{elem}, nil
}

// parseCommaElement validates and coerces one element of a comma-form list (or
// a single `.add` value) against the list's element type.
func parseCommaElement(p string, elem reflect.Type) (any, error) {
	for elem.Kind() == reflect.Pointer {
		elem = elem.Elem()
	}
	if p == "" {
		return nil, fmt.Errorf("empty element")
	}
	switch elem.Kind() {
	case reflect.Bool:
		b, err := strconv.ParseBool(p)
		if err != nil {
			return nil, fmt.Errorf("%q is not a boolean", p)
		}
		return b, nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("%q is not an integer", p)
		}
		return n, nil
	case reflect.Float32, reflect.Float64:
		f, err := strconv.ParseFloat(p, 64)
		if err != nil {
			return nil, fmt.Errorf("%q is not a number", p)
		}
		return f, nil
	case reflect.String, reflect.Interface:
		if jsonResidue(p) {
			return nil, fmt.Errorf("%q looks like a fragment of a JSON list; pass the whole list as JSON, e.g. '[\"a\",\"b\"]'", p)
		}
		return p, nil
	default:
		return nil, fmt.Errorf("elements of %s cannot be written in the comma form; pass JSON", describeType(elem))
	}
}

// jsonResidue reports whether a comma-split element still carries the quotes
// or brackets of a JSON list that was split instead of parsed.
func jsonResidue(p string) bool {
	return strings.ContainsAny(p[:1], `"'[`) || strings.ContainsAny(p[len(p)-1:], `"']`)
}

// parseStructuredValue parses a YAML (and so JSON) flow value and checks it
// against the field's declared type. The generic form is returned, because
// that is what the raw settings map holds.
//
// The shape check runs on the generic value because yaml.v3 decodes a number
// into a string field without complaint: `[1,2]` into []string would otherwise
// be stored as ["1","2"]. The typed decode then runs as the final authority for
// what the shape check does not model (struct fields).
func parseStructuredValue(value string, declared reflect.Type) (any, error) {
	var generic any
	if err := yaml.Unmarshal([]byte(value), &generic); err != nil {
		return nil, fmt.Errorf("cannot parse %q as %s: %v", value, describeType(declared), yamlErrText(err))
	}
	if err := checkShape(generic, declared); err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal([]byte(value), reflect.New(declared).Interface()); err != nil {
		return nil, fmt.Errorf("expected %s: %v", describeType(declared), yamlErrText(err))
	}
	return generic, nil
}

func yamlErrText(err error) string {
	return strings.TrimPrefix(err.Error(), "yaml: ")
}

// checkShape verifies a generically decoded value against a declared type.
// String elements must also be non-empty after trimming: an empty pattern in a
// scope list matches nothing (include) or everything (substring exclude).
func checkShape(v any, t reflect.Type) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	mismatch := func() error {
		return fmt.Errorf("expected %s, got %s", describeType(t), describeValue(v))
	}
	if v == nil {
		return mismatch()
	}
	switch t.Kind() {
	case reflect.Interface:
		return nil
	case reflect.String:
		s, ok := v.(string)
		if !ok {
			return mismatch()
		}
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("empty string")
		}
	case reflect.Bool:
		if _, ok := v.(bool); !ok {
			return mismatch()
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		switch v.(type) {
		case int, int64, uint64:
		default:
			return mismatch()
		}
	case reflect.Float32, reflect.Float64:
		switch v.(type) {
		case int, int64, uint64, float64:
		default:
			return mismatch()
		}
	case reflect.Slice, reflect.Array:
		list, ok := v.([]any)
		if !ok {
			return mismatch()
		}
		for i, e := range list {
			if err := checkShape(e, t.Elem()); err != nil {
				return fmt.Errorf("expected %s; element %d: %v", describeType(t), i, err)
			}
		}
	case reflect.Map:
		m, ok := v.(map[string]any)
		if !ok {
			return mismatch()
		}
		for k, e := range m {
			if err := checkShape(e, t.Elem()); err != nil {
				return fmt.Errorf("expected %s; key %q: %v", describeType(t), k, err)
			}
		}
	case reflect.Struct:
		if _, ok := v.(map[string]any); !ok {
			return mismatch()
		}
	}
	return nil
}

// describeType names a declared type the way an error message should.
func describeType(t reflect.Type) string {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Slice, reflect.Array:
		return "a list of " + pluralType(t.Elem())
	case reflect.Map:
		return "a map of names to " + pluralType(t.Elem())
	}
	return "a" + article(singularType(t)) + singularType(t)
}

func article(word string) string {
	if word != "" && strings.ContainsRune("aeiou", rune(word[0])) {
		return "n "
	}
	return " "
}

func singularType(t reflect.Type) string {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.String:
		return "string"
	case reflect.Bool:
		return "boolean"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "integer"
	case reflect.Float32, reflect.Float64:
		return "number"
	case reflect.Slice, reflect.Array:
		return "list"
	case reflect.Map, reflect.Struct:
		return "object"
	}
	return "value"
}

func pluralType(t reflect.Type) string {
	return singularType(t) + "s"
}

// describeValue names the shape of a generically decoded YAML value.
func describeValue(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "a string"
	case bool:
		return "a boolean"
	case int, int64, uint64:
		return "an integer"
	case float64:
		return "a number"
	case []any:
		return "a list"
	case map[string]any:
		return "a map"
	}
	return fmt.Sprintf("%T", v)
}
