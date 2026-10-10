package yamlext

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// SchemaIssue is one key in a .vgm.yaml file that the ExtensionDef schema does
// not have, with where it is and the closest key the schema does have.
type SchemaIssue struct {
	Path       string // dotted field path, e.g. "matchers[0].contians"
	Key        string // the unknown key as written
	Suggestion string // closest known key at that level, "" when none is close
	Line       int
	Col        int
}

// Message renders the issue the way lint and the loader report it.
func (i SchemaIssue) Message() string {
	msg := fmt.Sprintf("unknown key %q", i.Key)
	if i.Path != i.Key {
		msg = fmt.Sprintf("unknown key %q at %s", i.Key, i.Path)
	}
	if i.Suggestion != "" {
		msg += fmt.Sprintf(" (did you mean %q?)", i.Suggestion)
	}
	return msg
}

// parseDocument parses src into its root mapping node. It returns nil without
// an error for an empty document.
func parseDocument(src []byte) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, err
	}
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		return doc.Content[0], nil
	}
	if doc.Kind == 0 {
		return nil, nil
	}
	return &doc, nil
}

// checkSchema walks root against ExtensionDef and reports every unknown key
// (yaml.v3's KnownFields stops at the first one, and without a suggestion).
// fieldLines receives the line of every known key, by dotted path, so semantic
// lint issues can point at the field they are about.
func checkSchema(root *yaml.Node) (issues []SchemaIssue, fieldLines map[string]int) {
	fieldLines = map[string]int{}
	if root == nil {
		return nil, fieldLines
	}
	walkSchema(root, reflect.TypeOf(ExtensionDef{}), "", func(path string, key *yaml.Node, known []string) {
		if known == nil {
			fieldLines[path] = key.Line
			return
		}
		issues = append(issues, SchemaIssue{
			Path: path, Key: key.Value, Suggestion: closestKey(key.Value, known),
			Line: key.Line, Col: key.Column,
		})
	})
	return issues, fieldLines
}

// walkSchema visits every mapping key under n against Go type t. known is nil
// for a key the type has, and the sorted list of the type's keys for one it
// lacks (which is not descended into).
func walkSchema(n *yaml.Node, t reflect.Type, path string, visit func(path string, key *yaml.Node, known []string)) {
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
		fields := yamlFieldTypes(t)
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, val := n.Content[i], n.Content[i+1]
			if key.Value == "<<" {
				continue // YAML merge key
			}
			child := joinPath(path, key.Value)
			ft, ok := fields[key.Value]
			if !ok {
				visit(child, key, sortedFieldNames(fields))
				continue
			}
			visit(child, key, nil)
			walkSchema(val, ft, child, visit)
		}
	case reflect.Slice:
		if n.Kind != yaml.SequenceNode {
			return
		}
		for i, item := range n.Content {
			walkSchema(item, t.Elem(), fmt.Sprintf("%s[%d]", path, i), visit)
		}
	}
}

// yamlFieldTypes maps a struct's yaml key names to their field types.
func yamlFieldTypes(t reflect.Type) map[string]reflect.Type {
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

func sortedFieldNames(m map[string]reflect.Type) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func joinPath(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "." + name
}

// closestKey suggests the known key within a small edit distance of name: at
// most 2, or a third of the name's length for long keys.
func closestKey(name string, known []string) string {
	limit := 2
	if l := len(name) / 3; l > limit {
		limit = l
	}
	best, bestDist := "", limit+1
	for _, k := range known {
		if d := levenshtein(strings.ToLower(name), k); d < bestDist {
			best, bestDist = k, d
		}
	}
	return best
}

func levenshtein(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}
