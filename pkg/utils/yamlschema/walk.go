// Package yamlschema checks a parsed YAML document against the Go type it
// decodes into: every mapping key is matched to a struct field (by its yaml
// tag), so a caller can report each unknown key with its position and the
// closest known key, which yaml.v3's KnownFields cannot (it stops at the first
// one, without a suggestion).
package yamlschema

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"

	"github.com/vigolium/vigolium/pkg/utils/textutil"
	"gopkg.in/yaml.v3"
)

// Options tune Walk.
type Options struct {
	// CaseFold matches keys to fields case-insensitively when there is no
	// exact match, as encoding/json does (for JSON parsed as YAML).
	CaseFold bool
	// MapKeys visits the keys of a map-typed field (as known keys) instead of
	// stopping at the map.
	MapKeys bool
}

// Visitor receives one mapping key: its dotted path ("matchers[0].contains"),
// its node, and known — nil for a key the type has, and the sorted keys of the
// type for one it lacks (an unknown key, which is not descended into).
type Visitor func(path string, key *yaml.Node, known []string)

// Walk visits every mapping key under n against Go type t, path being n's own
// dotted path ("" at the root). Aliases are followed, YAML merge keys skipped,
// and a node whose kind does not fit the type is left to the decoder.
func Walk(n *yaml.Node, t reflect.Type, path string, opts Options, visit Visitor) {
	for n.Kind == yaml.AliasNode && n.Alias != nil {
		n = n.Alias
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		if n.Kind != yaml.MappingNode {
			return // a type mismatch; the decoder reports it
		}
		fields := fieldTypes(t)
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, val := n.Content[i], n.Content[i+1]
			if key.Value == "<<" {
				continue // YAML merge key
			}
			child := JoinPath(path, key.Value)
			ft, ok := fields[key.Value]
			if !ok && opts.CaseFold {
				for name, typ := range fields {
					if strings.EqualFold(name, key.Value) {
						ft, ok = typ, true
						break
					}
				}
			}
			if !ok {
				visit(child, key, slices.Sorted(maps.Keys(fields)))
				continue
			}
			visit(child, key, nil)
			Walk(val, ft, child, opts, visit)
		}
	case reflect.Slice:
		if n.Kind != yaml.SequenceNode {
			return
		}
		for i, item := range n.Content {
			Walk(item, t.Elem(), fmt.Sprintf("%s[%d]", path, i), opts, visit)
		}
	case reflect.Map:
		if !opts.MapKeys || n.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			visit(JoinPath(path, n.Content[i].Value), n.Content[i], nil)
		}
	}
}

// JoinPath appends name to a dotted field path.
func JoinPath(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "." + name
}

// Closest returns the known key nearest to name (lowercased) by edit
// distance, or "" when none is within limit edits. Ties go to the first in
// known.
func Closest(name string, known []string, limit int) string {
	name = strings.ToLower(name)
	best, bestDist := "", limit+1
	for _, k := range known {
		if d := textutil.Levenshtein(name, k); d < bestDist {
			best, bestDist = k, d
		}
	}
	return best
}

// fieldTypes maps a struct's yaml key names (the tag name, else the lowercased
// field name) to their field types.
func fieldTypes(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		out[name] = f.Type
	}
	return out
}
