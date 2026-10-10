package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3gen"

	"github.com/vigolium/vigolium/pkg/server"
)

const componentRefPrefix = "#/components/schemas/"

// generate rebuilds components.schemas of the given OpenAPI document from
// server.SwaggerSchemaTypes and returns the re-encoded document. Paths, tags
// and every other top-level section are kept verbatim; hand-written prose on a
// schema (descriptions, examples, enums, defaults, required lists) is carried
// over for every property that still exists. Output is deterministic (sorted
// keys, two-space indent, trailing newline) so `make verify-generated` can diff
// it.
func generate(spec []byte) ([]byte, error) {
	doc, err := decodeJSON(spec)
	if err != nil {
		return nil, fmt.Errorf("parse spec: %w", err)
	}
	root, ok := doc.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("spec is not a JSON object")
	}
	components, _ := root["components"].(map[string]any)
	if components == nil {
		components = map[string]any{}
		root["components"] = components
	}
	oldSchemas, _ := components["schemas"].(map[string]any)

	byType := make(map[reflect.Type]string, len(server.SwaggerSchemaTypes))
	for name, v := range server.SwaggerSchemaTypes {
		t := reflect.TypeOf(v)
		if prev, dup := byType[t]; dup {
			return nil, fmt.Errorf("type %s registered twice (%s, %s)", t, prev, name)
		}
		byType[t] = name
	}

	newSchemas := make(map[string]any, len(server.SwaggerSchemaTypes))
	for name, v := range server.SwaggerSchemaTypes {
		gen, err := schemaFor(reflect.TypeOf(v), byType)
		if err != nil {
			return nil, fmt.Errorf("generate %s: %w", name, err)
		}
		old, _ := oldSchemas[name].(map[string]any)
		newSchemas[name] = mergeSchema(gen, old)
	}
	for name := range server.SwaggerHandWrittenSchemas {
		s, ok := oldSchemas[name]
		if !ok {
			return nil, fmt.Errorf("hand-written schema %s is missing from the spec", name)
		}
		newSchemas[name] = s
	}
	components["schemas"] = newSchemas

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(root); err != nil {
		return nil, err
	}
	out := buf.Bytes()

	loaded, err := openapi3.NewLoader().LoadFromData(out)
	if err != nil {
		return nil, fmt.Errorf("generated spec does not load: %w", err)
	}
	if err := loaded.Validate(context.Background()); err != nil {
		return nil, fmt.Errorf("generated spec does not validate: %w", err)
	}
	return out, nil
}

// schemaFor generates the schema for t with encoding/json field naming and
// turns every nested struct that has its own registry entry into a $ref.
func schemaFor(t reflect.Type, byType map[reflect.Type]string) (map[string]any, error) {
	types := make(map[*openapi3.Schema]reflect.Type)
	gen := openapi3gen.NewGenerator(
		// encoding/json serialises untagged exported fields under their Go
		// name, so they belong in the schema too.
		openapi3gen.UseAllExportedFields(),
		openapi3gen.CreateFieldNameGenerator(jsonFieldName),
		// Self-referencing types (AgentSessionDetail.child_runs) come back as
		// a cycle $ref; name it after the registry entry.
		openapi3gen.CreateTypeNameGenerator(func(t reflect.Type) string {
			if name, ok := byType[t]; ok {
				return name
			}
			return t.Name()
		}),
		openapi3gen.SchemaCustomizer(func(_ string, t reflect.Type, _ reflect.StructTag, s *openapi3.Schema) error {
			types[s] = t
			return nil
		}),
	)
	ref, err := gen.NewSchemaRefForValue(reflect.New(t).Elem().Interface(), nil)
	if err != nil {
		return nil, err
	}
	if ref.Value == nil {
		return nil, fmt.Errorf("no schema produced")
	}
	refNested(ref.Value, types, byType, map[*openapi3.Schema]bool{})

	raw, err := json.Marshal(ref.Value)
	if err != nil {
		return nil, err
	}
	v, err := decodeJSON(raw)
	if err != nil {
		return nil, err
	}
	m, _ := v.(map[string]any)
	return m, nil
}

// refNested replaces child schemas generated from registered types with a
// component $ref.
func refNested(s *openapi3.Schema, types map[*openapi3.Schema]reflect.Type, byType map[reflect.Type]string, seen map[*openapi3.Schema]bool) {
	if s == nil || seen[s] {
		return
	}
	seen[s] = true
	visit := func(r *openapi3.SchemaRef) *openapi3.SchemaRef {
		if r == nil || r.Value == nil {
			return r
		}
		if name, ok := byType[types[r.Value]]; ok {
			return openapi3.NewSchemaRef(componentRefPrefix+name, nil)
		}
		refNested(r.Value, types, byType, seen)
		return r
	}
	for k, p := range s.Properties {
		s.Properties[k] = visit(p)
	}
	s.Items = visit(s.Items)
	if s.AdditionalProperties.Schema != nil {
		s.AdditionalProperties.Schema = visit(s.AdditionalProperties.Schema)
	}
}

// jsonFieldName mirrors encoding/json: the json tag name, else the Go field
// name. (openapi3gen would otherwise fall back to the yaml tag.)
func jsonFieldName(f reflect.StructField, _ string) string {
	if name, _, _ := strings.Cut(f.Tag.Get("json"), ","); name != "" {
		return name
	}
	return f.Name
}

// carriedKeys are hand-written schema annotations preserved across
// regeneration. Value-shaped ones are only kept while the type still matches.
var (
	carriedProse = []string{"description", "title", "deprecated", "readOnly", "writeOnly"}
	carriedTyped = []string{"example", "enum", "default", "format", "minimum", "maximum", "minLength", "maxLength", "pattern"}
)

// mergeSchema overlays hand-written annotations from old onto the generated
// schema gen. The generated structure (type, properties, items) wins; old
// prose survives for properties that still exist. A generated schema with no
// structure at all (an interface{} or json.RawMessage field) keeps the
// hand-written one wholesale, since it is strictly more informative.
func mergeSchema(gen, old map[string]any) map[string]any {
	if old == nil {
		return gen
	}
	if _, isRef := gen["$ref"]; isRef {
		return gen
	}
	if isUntyped(gen) {
		out := cloneMap(old)
		if n, ok := gen["nullable"]; ok {
			out["nullable"] = n
		}
		return out
	}
	for _, k := range carriedProse {
		if v, ok := old[k]; ok {
			if _, set := gen[k]; !set {
				gen[k] = v
			}
		}
	}
	for k, v := range old {
		if strings.HasPrefix(k, "x-") {
			gen[k] = v
		}
	}
	if sameType(gen, old) {
		for _, k := range carriedTyped {
			if v, ok := old[k]; ok {
				if _, set := gen[k]; !set {
					gen[k] = v
				}
			}
		}
	}

	genProps, _ := gen["properties"].(map[string]any)
	oldProps, _ := old["properties"].(map[string]any)
	for name, p := range genProps {
		gp, _ := p.(map[string]any)
		op, _ := oldProps[name].(map[string]any)
		if gp != nil && op != nil {
			genProps[name] = mergeSchema(gp, op)
		}
	}
	if req, ok := old["required"].([]any); ok && genProps != nil {
		var kept []any
		for _, r := range req {
			if s, ok := r.(string); ok {
				if _, exists := genProps[s]; exists {
					kept = append(kept, s)
				}
			}
		}
		if len(kept) > 0 {
			sort.Slice(kept, func(i, j int) bool { return kept[i].(string) < kept[j].(string) })
			gen["required"] = kept
		}
	}
	if gi, ok := gen["items"].(map[string]any); ok {
		if oi, ok := old["items"].(map[string]any); ok {
			gen["items"] = mergeSchema(gi, oi)
		}
	}
	if ga, ok := gen["additionalProperties"].(map[string]any); ok {
		if oa, ok := old["additionalProperties"].(map[string]any); ok {
			gen["additionalProperties"] = mergeSchema(ga, oa)
		}
	}
	return gen
}

func isUntyped(s map[string]any) bool {
	for _, k := range []string{"type", "$ref", "properties", "items", "additionalProperties", "oneOf", "anyOf", "allOf"} {
		if _, ok := s[k]; ok {
			return false
		}
	}
	return true
}

func sameType(a, b map[string]any) bool {
	bt, ok := b["type"]
	if !ok {
		return true
	}
	return fmt.Sprint(a["type"]) == fmt.Sprint(bt)
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func decodeJSON(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}
