package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"go.uber.org/zap"
)

// Module error kinds, the error_kind of a module.error event. "load" is the
// fourth value on the wire; it belongs to extension.failed's loader, not to a
// module call, so the executor never produces it.
const (
	ModuleErrorException = "exception"
	ModuleErrorTimeout   = "timeout"
	ModuleErrorPanic     = "panic"
)

// Rate limit for module.error events, per module: the first moduleErrorBurst
// occurrences, then every moduleErrorEvery-th. Each line's count is the running
// total, so a consumer reading only the last line still has the right number.
const (
	moduleErrorBurst = 3
	moduleErrorEvery = 100
)

// extensionModulePrefix marks a user extension's module id (pkg/jsext names
// every JS/YAML extension "ext-<id>"). Mirrors verify.ExtensionModulePrefix,
// which pkg/core cannot import.
const extensionModulePrefix = "ext-"

// IsExtensionModule reports whether a module id belongs to a user extension.
func IsExtensionModule(id string) bool { return strings.HasPrefix(id, extensionModulePrefix) }

// modulePanicError is the error runScanFnGuarded returns for a recovered module
// panic, typed so the error ledger can tell a panic from an ordinary error.
type modulePanicError struct {
	moduleID string
	value    any
}

func (e *modulePanicError) Error() string {
	return fmt.Sprintf("module %s panicked: %v", e.moduleID, e.value)
}

// moduleErrorKind classifies an error a module call returned.
func moduleErrorKind(err error) string {
	var p *modulePanicError
	if errors.As(err, &p) {
		return ModuleErrorPanic
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ModuleErrorTimeout
	}
	return ModuleErrorException
}

// moduleErrorCounts is an executor's own per-module error tally (all kinds).
// The zero value is ready to use.
type moduleErrorCounts struct {
	m sync.Map // module id → *atomic.Int64
}

func (c *moduleErrorCounts) add(id string) int64 {
	v, ok := c.m.Load(id)
	if !ok {
		v, _ = c.m.LoadOrStore(id, new(atomic.Int64))
	}
	return v.(*atomic.Int64).Add(1)
}

func (c *moduleErrorCounts) snapshot() map[string]int64 {
	out := make(map[string]int64)
	c.m.Range(func(k, v any) bool {
		out[k.(string)] = v.(*atomic.Int64).Load()
		return true
	})
	return out
}

// ModuleErrors returns this executor's per-module error counts (exceptions,
// timeouts and panics), keyed by module id. Empty when no module failed.
func (e *Executor) ModuleErrors() map[string]int64 {
	return e.moduleErrs.snapshot()
}

// noteModuleError records one failed module call: it counts it (on the
// executor and, through ExecutorConfig.OnModuleError, on the owner's ledger),
// logs it, and emits a rate-limited module.error event. Called next to every
// moduleMetrics.Record that carries an error, on the per-module timeout arms,
// and for recovered panics. kind is one of the ModuleError* constants.
//
// Logging: an extension's first failure is a Warn (it is the operator's own
// code, and an exception on every item otherwise looks like a clean run), later
// ones Debug; a built-in passive module's errors stay at Debug; a built-in
// active module's errors stay at Warn, as before.
func (e *Executor) noteModuleError(module modules.Module, item *httpmsg.HttpRequestResponse, err error, kind string) {
	if module == nil {
		return
	}
	id := module.ID()
	total := e.moduleErrs.add(id)
	if e.cfg.OnModuleError != nil {
		total = e.cfg.OnModuleError(id, kind)
	}

	msg := ""
	if err != nil {
		msg = err.Error()
	}
	switch {
	case IsExtensionModule(id) && total == 1:
		zap.L().Warn("Extension module failed; further failures are counted in module_errors (vigolium log --scan-uuid <uuid>)",
			zap.String("module", id), zap.String("kind", kind), zap.String("error", msg))
	case IsExtensionModule(id), kind == ModuleErrorTimeout:
		// Extensions after their first failure, and timeouts (their call sites
		// keep their own log line).
		zap.L().Debug("Module error", zap.String("module", id), zap.String("kind", kind), zap.String("error", msg))
	default:
		if _, active := module.(modules.ActiveModule); active {
			zap.L().Warn("Active module error", zap.String("module", id), zap.String("kind", kind), zap.String("error", msg))
		} else {
			zap.L().Debug("Passive module error", zap.String("module", id), zap.String("kind", kind), zap.String("error", msg))
		}
	}

	if total > moduleErrorBurst && total%moduleErrorEvery != 0 {
		return
	}
	if !scanevents.On() {
		return
	}
	ev := scanevents.Event{
		Type:      scanevents.TypeModuleError,
		ModuleID:  id,
		Phase:     e.cfg.Phase,
		ErrorKind: kind,
		Message:   msg,
		Count:     scanevents.Int64(total),
	}
	if item != nil {
		ev.URL = item.Target()
	}
	scanevents.Emit(ev)
}
