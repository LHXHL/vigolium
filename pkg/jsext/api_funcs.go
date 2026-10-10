package jsext

import (
	"strings"

	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/pkg/jsext/api/parse"
)

// The namespace constants, JSFuncDef, HandlerFactory, APIOptions, and
// APIFunction types live in the leaf package pkg/jsext/api and are re-exported
// from this package via aliases in api_aliases.go.

// ─── Collection ─────────────────────────────────────────────────────────────

// allFuncDefs returns every JS API function definition.
// The returned slice is the single source of truth for both VM registration
// and the documentation catalog.
func allFuncDefs() []JSFuncDef {
	var all []JSFuncDef
	all = append(all, logFuncDefs()...)
	all = append(all, utilsFuncDefs()...)
	all = append(all, parse.FuncDefs()...)
	all = append(all, httpCoreFuncDefs()...)
	all = append(all, httpSessionFuncDefs()...)
	all = append(all, httpAuthTestFuncDefs()...)
	all = append(all, httpSessionPoolFuncDefs()...)
	all = append(all, httpHelperFuncDefs()...)
	all = append(all, httpGraphQLFuncDefs()...)
	all = append(all, httpCacheFuncDefs()...)
	all = append(all, scanFuncDefs()...)
	all = append(all, ingestFuncDefs()...)
	all = append(all, agentFuncDefs()...)
	all = append(all, dbFuncDefs()...)
	all = append(all, oastFuncDefs()...)
	all = append(all, payloadsFuncDefs()...)
	all = append(all, recordFuncDefs()...)
	all = append(all, configFuncDefs()...)
	all = append(all, mcpFuncDefs()...)
	return all
}

// ─── Registration ───────────────────────────────────────────────────────────

// registerFuncs iterates over all JSFuncDefs, creates namespace objects as
// needed, calls each MakeHandler, and registers the resulting function on
// the appropriate namespace object.
//
// In ModeRuntime, namespaces are skipped when their required dependencies are
// not available (see shouldRegisterNS). In ModeLoad every namespace is
// registered regardless, so top-level code sees the runtime's API shape: pure
// handlers are real and every effectful one is a loadTimeStub.
func registerFuncs(vm *sobek.Runtime, opts APIOptions, defs []JSFuncDef) {
	nsCache := make(map[string]*sobek.Object)
	nsCache[NsRoot] = vm.Get(NsRoot).ToObject(vm)

	for _, def := range defs {
		if def.MakeHandler == nil {
			continue // metadata-only
		}
		if opts.Mode == ModeLoad {
			obj := getOrCreateNS(vm, nsCache, def.Namespace)
			if def.Effect == EffectPure {
				_ = obj.Set(def.Name, def.MakeHandler(vm, opts))
			} else {
				_ = obj.Set(def.Name, loadTimeStub(vm, def, opts.OnLoadEffect))
			}
			continue
		}
		if !shouldRegisterNS(def.Namespace, opts) {
			continue
		}
		obj := getOrCreateNS(vm, nsCache, def.Namespace)
		handler := def.MakeHandler(vm, opts)
		_ = obj.Set(def.Name, handler)
	}
}

// loadTimeStub stands in for an effectful API function while a script is
// loaded or linted. It does nothing, returns an empty value of the declared
// return type, and reports the call (with the calling line) to report.
func loadTimeStub(vm *sobek.Runtime, def JSFuncDef, report func(EffectCall)) func(sobek.FunctionCall) sobek.Value {
	name := def.FullName()
	return func(sobek.FunctionCall) sobek.Value {
		if report != nil {
			c := EffectCall{API: name, Effect: def.Effect}
			for _, f := range vm.CaptureCallStack(0, nil) {
				if pos := f.Position(); pos.Line > 0 {
					c.Line, c.Col = pos.Line, pos.Column
					break
				}
			}
			report(c)
		}
		return stubReturnValue(vm, def.Returns)
	}
}

// stubReturnValue is the empty value of a declared return type: undefined for
// void, null for a nullable type, [] for an array, false/""/0 for scalars, and
// {} for any object type, so top-level code that reads a property of the result
// keeps running.
func stubReturnValue(vm *sobek.Runtime, returns string) sobek.Value {
	r := strings.ToLower(strings.TrimSpace(returns))
	switch {
	case r == "" || r == "void":
		return sobek.Undefined()
	case strings.Contains(r, "null"):
		return sobek.Null()
	case strings.HasSuffix(r, "[]") || strings.HasPrefix(r, "["):
		return vm.NewArray()
	case r == "bool" || r == "boolean":
		return vm.ToValue(false)
	case r == "string":
		return vm.ToValue("")
	case r == "number":
		return vm.ToValue(0)
	default:
		return vm.NewObject()
	}
}

// registerFuncsUnchecked is like registerFuncs but skips the namespace
// dependency check. Used in tests to register handlers even when optional
// dependencies (e.g. Repository) are nil.
func registerFuncsUnchecked(vm *sobek.Runtime, opts APIOptions, defs []JSFuncDef) {
	nsCache := make(map[string]*sobek.Object)
	nsCache[NsRoot] = vm.Get(NsRoot).ToObject(vm)

	for _, def := range defs {
		if def.MakeHandler == nil {
			continue
		}
		obj := getOrCreateNS(vm, nsCache, def.Namespace)
		handler := def.MakeHandler(vm, opts)
		_ = obj.Set(def.Name, handler)
	}
}

// shouldRegisterNS returns false when the required dependencies for a
// namespace are not available, matching the conditional logic that was
// previously in SetupAPI.
func shouldRegisterNS(ns string, opts APIOptions) bool {
	switch {
	case ns == NsHTTP || strings.HasPrefix(ns, NsHTTP+"."):
		return opts.HTTPClient != nil
	case ns == NsMCP || strings.HasPrefix(ns, NsMCP+"."):
		return opts.HTTPClient != nil
	case ns == NsIngest || strings.HasPrefix(ns, NsIngest+"."):
		return opts.Repository != nil
	case ns == NsDB || strings.HasPrefix(ns, NsDB+"."):
		return opts.Repository != nil
	case ns == NsAgent || strings.HasPrefix(ns, NsAgent+"."):
		return opts.LLMClient != nil
	case ns == NsOAST || strings.HasPrefix(ns, NsOAST+"."):
		return opts.OASTService != nil
	default:
		return true
	}
}

// getOrCreateNS returns the *sobek.Object for a dot-separated namespace,
// creating intermediate objects as needed.
func getOrCreateNS(vm *sobek.Runtime, cache map[string]*sobek.Object, ns string) *sobek.Object {
	if obj, ok := cache[ns]; ok {
		return obj
	}

	parts := strings.Split(ns, ".")
	parentNS := strings.Join(parts[:len(parts)-1], ".")
	leafName := parts[len(parts)-1]

	parent := getOrCreateNS(vm, cache, parentNS)

	// Reuse existing object if the namespace was already set on the parent.
	if existing := parent.Get(leafName); existing != nil && !sobek.IsUndefined(existing) && !sobek.IsNull(existing) {
		obj := existing.ToObject(vm)
		cache[ns] = obj
		return obj
	}

	obj := vm.NewObject()
	_ = parent.Set(leafName, obj)
	cache[ns] = obj
	return obj
}
