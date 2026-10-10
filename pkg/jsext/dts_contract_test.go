package jsext

import (
	"bufio"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var (
	dtsNamespaceRe = regexp.MustCompile(`^\s*(?:declare\s+)?namespace\s+([\w.]+)\s*\{`)
	dtsFunctionRe  = regexp.MustCompile(`^\s*function\s+(\w+)\s*[(<]`)
)

// dtsDeclaredFunctions returns the fully-qualified name of every function
// declared inside a namespace of the embedded vigolium.d.ts (for example
// "vigolium.db.records.query"). Constants (vigolium.config, vigolium.record)
// and top-level interfaces/types are not functions and are ignored.
func dtsDeclaredFunctions(t *testing.T) map[string]bool {
	t.Helper()

	type frame struct {
		name  string
		depth int
	}
	var stack []frame
	depth := 0
	out := make(map[string]bool)

	sc := bufio.NewScanner(strings.NewReader(TypeDefinitions()))
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if m := dtsNamespaceRe.FindStringSubmatch(line); m != nil {
			name := m[1]
			if len(stack) > 0 {
				name = stack[len(stack)-1].name + "." + name
			}
			depth++
			stack = append(stack, frame{name: name, depth: depth})
			continue
		}
		if m := dtsFunctionRe.FindStringSubmatch(line); m != nil && len(stack) > 0 && depth == stack[len(stack)-1].depth {
			out[stack[len(stack)-1].name+"."+m[1]] = true
		}
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		for len(stack) > 0 && depth < stack[len(stack)-1].depth {
			stack = stack[:len(stack)-1]
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan vigolium.d.ts: %v", err)
	}
	if depth != 0 {
		t.Fatalf("vigolium.d.ts braces are unbalanced (depth %d at EOF); the drift parser cannot be trusted", depth)
	}
	return out
}

// TestDTSMatchesRegisteredFuncs keeps vigolium.d.ts a checked artifact: every
// function it declares must be registered by allFuncDefs(), and every
// registered function must be declared. vigolium.config.<key> and
// vigolium.record.<field> are metadata-only properties (declared in the d.ts
// as the `config` and `record` constants), so they are excluded.
func TestDTSMatchesRegisteredFuncs(t *testing.T) {
	declared := dtsDeclaredFunctions(t)
	if len(declared) < 50 {
		t.Fatalf("parsed only %d functions from vigolium.d.ts; the drift parser is broken", len(declared))
	}

	registered := make(map[string]bool)
	for _, def := range allFuncDefs() {
		if def.MakeHandler == nil || def.Namespace == NsConfig || def.Namespace == NsRecord {
			continue
		}
		registered[def.FullName()] = true
	}

	var missingFromDTS, missingFromRuntime []string
	for name := range registered {
		if !declared[name] {
			missingFromDTS = append(missingFromDTS, name)
		}
	}
	for name := range declared {
		if !registered[name] {
			missingFromRuntime = append(missingFromRuntime, name)
		}
	}
	sort.Strings(missingFromDTS)
	sort.Strings(missingFromRuntime)

	if len(missingFromDTS) > 0 {
		t.Errorf("registered in allFuncDefs() but not declared in vigolium.d.ts:\n  %s", strings.Join(missingFromDTS, "\n  "))
	}
	if len(missingFromRuntime) > 0 {
		t.Errorf("declared in vigolium.d.ts but not registered by allFuncDefs():\n  %s", strings.Join(missingFromRuntime, "\n  "))
	}
}

func TestTypeDefinitionsEmbedded(t *testing.T) {
	src := TypeDefinitions()
	for _, want := range []string{"declare namespace vigolium", "interface ModuleExports", "declare var module"} {
		if !strings.Contains(src, want) {
			t.Errorf("embedded vigolium.d.ts is missing %q", want)
		}
	}
}
