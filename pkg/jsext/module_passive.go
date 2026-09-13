package jsext

import (
	"fmt"

	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// JSPassiveModule wraps a JS passive extension as a PassiveModule.
// No mutex needed — sync.Pool is thread-safe and each VM is an independent runtime.
type JSPassiveModule struct {
	modkit.BasePassiveModule
	script *LoadedScript
	pool   *VMPool
}

// NewJSPassiveModule creates a PassiveModule from a JS script.
func NewJSPassiveModule(script *LoadedScript, opts APIOptions) (*JSPassiveModule, error) {
	scanTypes := ParseScanScopes(script.Metadata.ScanTypes)
	sev := ParseSeverity(script.Metadata.Severity)
	scope := ParsePassiveScope(script.Metadata.Scope)

	pool, err := NewVMPool(script, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to compile JS script %s: %w", script.Path, err)
	}

	base := modkit.NewBasePassiveModule(
		"ext-"+script.Metadata.ID,
		script.Metadata.Name,
		script.Metadata.Description,
		"JS extension: "+script.Metadata.Name,
		script.Metadata.ConfirmationCriteria,
		sev,
		severity.Firm,
		scanTypes,
		scope,
	)
	base.ModuleTags = script.Metadata.Tags

	return &JSPassiveModule{
		BasePassiveModule: base,
		script:            script,
		pool:              pool,
	}, nil
}

func (m *JSPassiveModule) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	vm := m.pool.Get()
	// poisoned is set when the watchdog interrupted the runtime; such a VM carries
	// a sticky interrupt flag and must never go back into the pool.
	poisoned := false
	defer func() { m.pool.PutUnlessPoisoned(vm, poisoned) }()

	ctxObj := buildRequestContext(vm, ctx)
	enrichRecordContext(vm, ctxObj, ctx, scanCtx, m.pool.opts.Repository)

	exports := vm.Get("module").ToObject(vm).Get("exports").ToObject(vm)
	fn := exports.Get("scanPerRequest")
	if fn == nil || sobek.IsUndefined(fn) {
		return nil, nil
	}

	callable, ok := sobek.AssertFunction(fn)
	if !ok {
		return nil, fmt.Errorf("scanPerRequest is not a function in %s", m.script.Path)
	}

	// Bounded like the active path. Sobek runs JS synchronously with no built-in
	// cancellation, and the executor's inline passive path assumes a non-contextual
	// module does bounded work — which arbitrary user JavaScript does not. Calling
	// the extension unguarded meant one infinite loop in a passive extension pinned
	// a worker goroutine and a core for the rest of the scan.
	result, err, timedOut := callJSWithTimeout(vm, callable, exports, ctxObj)
	poisoned = timedOut
	if err != nil {
		return nil, fmt.Errorf("JS error in %s: %w", m.script.Path, err)
	}

	return parseJSResults(vm, result, ctx), nil
}

func (m *JSPassiveModule) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	vm := m.pool.Get()
	poisoned := false
	defer func() { m.pool.PutUnlessPoisoned(vm, poisoned) }()

	ctxObj := buildRequestContext(vm, ctx)
	enrichRecordContext(vm, ctxObj, ctx, scanCtx, m.pool.opts.Repository)

	exports := vm.Get("module").ToObject(vm).Get("exports").ToObject(vm)
	fn := exports.Get("scanPerHost")
	if fn == nil || sobek.IsUndefined(fn) {
		return nil, nil
	}

	callable, ok := sobek.AssertFunction(fn)
	if !ok {
		return nil, fmt.Errorf("scanPerHost is not a function in %s", m.script.Path)
	}

	result, err, timedOut := callJSWithTimeout(vm, callable, exports, ctxObj)
	poisoned = timedOut
	if err != nil {
		return nil, fmt.Errorf("JS error in %s: %w", m.script.Path, err)
	}

	return parseJSResults(vm, result, ctx), nil
}
