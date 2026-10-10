package server

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gofiber/fiber/v3"
)

// swaggerUndocumentedRoutes are registered routes that are deliberately not
// part of the OpenAPI document: static assets and the spec itself.
var swaggerUndocumentedRoutes = map[string]bool{
	"GET /favicon.ico":      true,
	"GET /swagger/doc.json": true,
}

// loadSwaggerDoc parses the embedded spec as a plain JSON tree.
func loadSwaggerDoc(t *testing.T) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(swaggerSpec, &doc); err != nil {
		t.Fatalf("embedded swagger spec is not valid JSON: %v", err)
	}
	return doc
}

// swaggerOperations returns the spec's "METHOD /path" set.
func swaggerOperations(t *testing.T, doc map[string]any) map[string]bool {
	t.Helper()
	paths, _ := doc["paths"].(map[string]any)
	ops := make(map[string]bool)
	for p, item := range paths {
		methods, _ := item.(map[string]any)
		for m := range methods {
			switch m {
			case "get", "put", "post", "delete", "patch", "head", "options", "trace":
				ops[strings.ToUpper(m)+" "+p] = true
			}
		}
	}
	return ops
}

// fiberPathToOpenAPI turns "/api/scans/:uuid" into "/api/scans/{uuid}" and a
// trailing wildcard into "{path}".
func fiberPathToOpenAPI(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		switch {
		case strings.HasPrefix(s, ":"):
			segs[i] = "{" + strings.TrimSuffix(strings.TrimPrefix(s, ":"), "?") + "}"
		case s == "*" || s == "+":
			segs[i] = "{path}"
		}
	}
	return strings.Join(segs, "/")
}

// registeredOperations walks the full production route table (every optional
// group enabled) and returns its "METHOD /path" set in OpenAPI form.
func registeredOperations(t *testing.T) map[string]bool {
	t.Helper()
	app := fiber.New()
	registerRoutes(app, &Handlers{}, ServerConfig{NoAuth: true})
	ops := make(map[string]bool)
	for _, r := range app.GetRoutes(true) {
		// Fiber registers HEAD alongside every GET; the spec documents the GET.
		if r.Method == http.MethodHead {
			continue
		}
		key := r.Method + " " + fiberPathToOpenAPI(r.Path)
		if swaggerUndocumentedRoutes[key] {
			continue
		}
		ops[key] = true
	}
	if len(ops) == 0 {
		t.Fatal("route walk found no routes")
	}
	return ops
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestSwaggerDocumentsEveryRoute: (a) every registered route has a spec
// operation, so a new endpoint cannot ship undocumented.
func TestSwaggerDocumentsEveryRoute(t *testing.T) {
	spec := swaggerOperations(t, loadSwaggerDoc(t))
	var missing []string
	for _, op := range sortedKeys(registeredOperations(t)) {
		if !spec[op] {
			missing = append(missing, op)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("registered routes missing from the swagger spec (add them to docs/development/api-swagger.json, then run `make swagger`):\n  %s",
			strings.Join(missing, "\n  "))
	}
}

// TestSwaggerHasNoPhantomRoutes: (b) every spec operation is registered, so
// the spec cannot advertise an endpoint that 404s.
func TestSwaggerHasNoPhantomRoutes(t *testing.T) {
	routes := registeredOperations(t)
	var phantom []string
	for _, op := range sortedKeys(swaggerOperations(t, loadSwaggerDoc(t))) {
		if !routes[op] {
			phantom = append(phantom, op)
		}
	}
	if len(phantom) > 0 {
		t.Fatalf("swagger spec documents operations that are not registered in routes.go:\n  %s",
			strings.Join(phantom, "\n  "))
	}
}

// jsonFieldNames returns the JSON object keys encoding/json produces for t:
// tagged name or Go field name, "-" and unexported fields dropped, untagged
// embedded structs flattened.
func jsonFieldNames(t reflect.Type) map[string]bool {
	names := make(map[string]bool)
	var walk func(reflect.Type)
	walk = func(t reflect.Type) {
		for t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct {
			return
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := f.Tag.Get("json")
			if tag == "-" {
				continue
			}
			name, _, _ := strings.Cut(tag, ",")
			ft := f.Type
			for ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if f.Anonymous && name == "" && ft.Kind() == reflect.Struct {
				walk(ft)
				continue
			}
			if !f.IsExported() {
				continue
			}
			switch f.Type.Kind() {
			case reflect.Func, reflect.Chan:
				continue
			}
			if name == "" {
				name = f.Name
			}
			names[name] = true
		}
	}
	walk(t)
	return names
}

// TestSwaggerSchemasMatchStructs: (c) every registered schema's property set
// equals its struct's JSON keys. This catches types.go drift (a field added,
// renamed or removed) without anyone remembering to regenerate the spec.
func TestSwaggerSchemasMatchStructs(t *testing.T) {
	schemas, _ := loadSwaggerDoc(t)["components"].(map[string]any)["schemas"].(map[string]any)
	names := make([]string, 0, len(SwaggerSchemaTypes))
	for n := range SwaggerSchemaTypes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		typ := reflect.TypeOf(SwaggerSchemaTypes[name])
		raw, ok := schemas[name].(map[string]any)
		if !ok {
			t.Errorf("%s: registered in SwaggerSchemaTypes but absent from components.schemas (run `make swagger`)", name)
			continue
		}
		if typ.Kind() != reflect.Struct {
			continue // map/slice aliases have no property set to compare
		}
		want := jsonFieldNames(typ)
		got := make(map[string]bool)
		props, _ := raw["properties"].(map[string]any)
		for p := range props {
			got[p] = true
		}
		var extra, missing []string
		for p := range got {
			if !want[p] {
				extra = append(extra, p)
			}
		}
		for p := range want {
			if !got[p] {
				missing = append(missing, p)
			}
		}
		sort.Strings(extra)
		sort.Strings(missing)
		if len(extra) > 0 || len(missing) > 0 {
			t.Errorf("%s (%s): spec properties drifted from the struct; missing %v, not in struct %v (run `make swagger`)",
				name, typ, missing, extra)
		}
	}
}

// TestSwaggerSchemasAreRegistered: every components.schemas entry is either
// generated from a registered type or explicitly hand-written, so orphaned
// schemas for removed endpoints do not linger.
func TestSwaggerSchemasAreRegistered(t *testing.T) {
	schemas, _ := loadSwaggerDoc(t)["components"].(map[string]any)["schemas"].(map[string]any)
	var orphans []string
	for name := range schemas {
		if _, ok := SwaggerSchemaTypes[name]; !ok && !SwaggerHandWrittenSchemas[name] {
			orphans = append(orphans, name)
		}
	}
	sort.Strings(orphans)
	if len(orphans) > 0 {
		t.Fatalf("components.schemas entries with no Go type in SwaggerSchemaTypes: %v", orphans)
	}
}

// TestSwaggerSpecValidates: (d) the embedded spec loads, resolves every $ref
// and validates as OpenAPI 3.
func TestSwaggerSpecValidates(t *testing.T) {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(swaggerSpec)
	if err != nil {
		t.Fatalf("load swagger spec: %v", err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatalf("swagger spec does not validate: %v", err)
	}
}
