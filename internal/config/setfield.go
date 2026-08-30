package config

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// SetField updates a field in the Settings struct using dot-notation key and string value.
// It round-trips through a map[string]any to handle arbitrary nesting.
func SetField(settings *Settings, key string, value string) error {
	// Marshal settings to YAML, then unmarshal into generic map
	data, err := yaml.Marshal(settings)
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("failed to unmarshal settings: %w", err)
	}

	// Split key into parts and navigate to the leaf
	parts := strings.Split(key, ".")
	if len(parts) == 0 {
		return fmt.Errorf("empty key")
	}

	// List-op suffix: `<list_path>.add <value>` appends; `<list_path>.clear`
	// resets to an empty list. Only fires when the parent path resolves to a
	// list (`[]any`) — otherwise fall through to normal scalar handling so a
	// legitimate scalar field literally named `add` or `clear` still works.
	if len(parts) >= 2 {
		last := parts[len(parts)-1]
		if last == "add" || last == "clear" {
			parentPath := parts[:len(parts)-1]
			parentMap, listKey, err := navigateToParent(raw, parentPath)
			if err == nil {
				if list, isList := parentMap[listKey].([]any); isList || parentMap[listKey] == nil {
					switch last {
					case "add":
						parentMap[listKey] = append(list, value)
					case "clear":
						parentMap[listKey] = []any{}
					}
					return marshalBack(raw, settings)
				}
			}
		}
	}

	// Navigate to the parent map, creating containers for segments that the
	// omitempty YAML round-trip dropped (an unset field like notify.telegram is
	// absent from `raw`). A missing segment is only created after the full key
	// validates against the Settings struct schema, so typos still error.
	current := raw
	for i := 0; i < len(parts)-1; i++ {
		child, ok := current[parts[i]]
		if !ok {
			if _, valid := resolveSettingKind(key); !valid {
				return fmt.Errorf("key %q not found (unknown segment %q)", key, parts[i])
			}
			newMap := map[string]any{}
			current[parts[i]] = newMap
			current = newMap
			continue
		}
		childMap, ok := child.(map[string]any)
		if !ok {
			return fmt.Errorf("key %q is not a map (at segment %q)", key, parts[i])
		}
		current = childMap
	}

	// Set the leaf. When it already exists in the round-tripped map, coerce
	// against its present value; when it was dropped by omitempty, coerce
	// against the field's declared kind (validating the key on the way).
	leafKey := parts[len(parts)-1]
	if existing, ok := current[leafKey]; ok {
		current[leafKey] = coerceValue(value, existing)
	} else {
		kind, valid := resolveSettingKind(key)
		if !valid {
			return fmt.Errorf("key %q not found (unknown segment %q)", key, leafKey)
		}
		current[leafKey] = coerceValueForKind(value, kind)
	}

	return marshalBack(raw, settings)
}

// resolveSettingKind walks the Settings struct type along the dot-notation key,
// following yaml tag names, and returns the reflect.Kind of the leaf value.
// ok is false when any segment names a field that does not exist (a typo).
// Descending through a map[string]X consumes one segment as a dynamic key and
// continues into X, so arbitrary keys under maps (e.g.
// known_issue_scan.severity_overrides.<code>) validate.
func resolveSettingKind(key string) (reflect.Kind, bool) {
	t := reflect.TypeOf(Settings{})
	for _, seg := range strings.Split(key, ".") {
		for t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		switch t.Kind() {
		case reflect.Struct:
			ft, ok := yamlFieldType(t, seg)
			if !ok {
				return reflect.Invalid, false
			}
			t = ft
		case reflect.Map:
			// seg is a dynamic map key; descend into the element type.
			t = t.Elem()
		default:
			// More segments remain but the current type is a scalar/slice.
			return reflect.Invalid, false
		}
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t.Kind(), true
}

// yamlFieldType returns the type of the struct field whose yaml tag name matches
// name. Fields tagged `yaml:"-"` are skipped; an empty tag name falls back to
// the yaml default (the lowercased field name).
func yamlFieldType(t reflect.Type, name string) (reflect.Type, bool) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("yaml")
		if tag == "-" {
			continue
		}
		tagName, _, _ := strings.Cut(tag, ",")
		if tagName == "" {
			tagName = strings.ToLower(f.Name)
		}
		if tagName == name {
			return f.Type, true
		}
	}
	return nil, false
}

// coerceValueForKind converts value to the concrete type implied by a struct
// field's declared reflect.Kind. It is used when the leaf key was dropped by
// omitempty (so there is no existing value to sniff the type from).
func coerceValueForKind(value string, kind reflect.Kind) any {
	switch kind {
	case reflect.Bool:
		return strings.EqualFold(value, "true") || value == "1"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if n, err := strconv.Atoi(value); err == nil {
			return n
		}
		return value
	case reflect.Float32, reflect.Float64:
		if n, err := strconv.ParseFloat(value, 64); err == nil {
			return n
		}
		return value
	case reflect.Slice, reflect.Array:
		parts := strings.Split(value, ",")
		result := make([]any, len(parts))
		for i, p := range parts {
			result[i] = strings.TrimSpace(p)
		}
		return result
	default:
		return value
	}
}

// navigateToParent walks `raw` along `parts[:len(parts)-1]` and returns the
// terminal parent map plus the final segment, so the caller can read or
// rewrite parent[final].
func navigateToParent(raw map[string]any, parts []string) (map[string]any, string, error) {
	if len(parts) == 0 {
		return nil, "", fmt.Errorf("empty path")
	}
	current := raw
	for i := 0; i < len(parts)-1; i++ {
		child, ok := current[parts[i]]
		if !ok {
			return nil, "", fmt.Errorf("unknown segment %q", parts[i])
		}
		childMap, ok := child.(map[string]any)
		if !ok {
			return nil, "", fmt.Errorf("segment %q is not a map", parts[i])
		}
		current = childMap
	}
	return current, parts[len(parts)-1], nil
}

// marshalBack writes the mutated `raw` map back into `settings` via YAML.
func marshalBack(raw map[string]any, settings *Settings) error {
	newData, err := yaml.Marshal(raw)
	if err != nil {
		return fmt.Errorf("failed to marshal updated config: %w", err)
	}
	if err := yaml.Unmarshal(newData, settings); err != nil {
		return fmt.Errorf("failed to unmarshal updated config: %w", err)
	}
	return nil
}

// coerceValue converts a string value to match the type of the existing value.
// When existing is nil — which happens for pointer fields (e.g. *bool) whose
// initial value marshals to YAML null — the value's shape is sniffed:
// "true"/"false" → bool, integers → int, decimals → float64, otherwise the
// raw string is returned. The sniff is conservative: only unambiguous shapes
// coerce; anything else falls through unchanged.
func coerceValue(value string, existing any) any {
	switch existing.(type) {
	case bool:
		return strings.EqualFold(value, "true") || value == "1"
	case int:
		if n, err := strconv.Atoi(value); err == nil {
			return n
		}
		return value
	case float64:
		if n, err := strconv.ParseFloat(value, 64); err == nil {
			return n
		}
		return value
	case []any:
		// Split comma-separated values
		parts := strings.Split(value, ",")
		result := make([]any, len(parts))
		for i, p := range parts {
			result[i] = strings.TrimSpace(p)
		}
		return result
	case nil:
		// Pointer field (e.g. *bool) whose initial value is nil — round-tripped
		// through YAML as null. Infer the type from the value's shape.
		// ParseBool is tried first because *bool is the only pointer scalar
		// in use today; if a *int or *float64 field is ever added, this
		// ordering must be revisited — values like "0" / "1" would coerce
		// to bool rather than the intended numeric type.
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
		if n, err := strconv.Atoi(value); err == nil {
			return n
		}
		if f, err := strconv.ParseFloat(value, 64); err == nil {
			return f
		}
		return value
	default:
		return value
	}
}
