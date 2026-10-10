package yamlext

import (
	"fmt"
	"reflect"

	"github.com/vigolium/vigolium/pkg/utils/yamlschema"
	"gopkg.in/yaml.v3"
)

// SchemaIssue is one key in a .vgm.yaml file that the ExtensionDef schema does
// not have, with where it is and the closest key the schema does have.
type SchemaIssue struct {
	Path       string // dotted field path, e.g. "matchers[0].contans"
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
	yamlschema.Walk(root, reflect.TypeOf(ExtensionDef{}), "", yamlschema.Options{}, func(path string, key *yaml.Node, known []string) {
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

// closestKey suggests the known key within a small edit distance of name: at
// most 2, or a third of the name's length for long keys.
func closestKey(name string, known []string) string {
	return yamlschema.Closest(name, known, max(2, len(name)/3))
}
