// Package exttest runs one extension against one HTTP message, outside a scan.
//
// It is the engine behind `vigolium ext eval --record-uuid` (one stored record,
// no network unless asked) and `vigolium ext test <dir>` (fixture files, active
// extensions answered by an in-process 127.0.0.1 mock). Both load the
// extension through jsext.NewEngine, the loader a scan uses, so a script that
// passes here loads the same way in a scan.
package exttest

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/jsext"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// NetworkDisabledMessage is the error every request of an offline run fails
// with; inside JavaScript, vigolium.http.* throws it.
const NetworkDisabledMessage = "network disabled in ext eval; pass --allow-network"

// NewOfflineRequester is the requester an offline run uses: every request is
// refused with NetworkDisabledMessage and counted (RequestsRefused).
func NewOfflineRequester() *http.Requester {
	return http.NewOfflineRequester(NetworkDisabledMessage)
}

// Handler names, as an extension exports them.
const (
	HandlerPerRequest        = "scanPerRequest"
	HandlerPerHost           = "scanPerHost"
	HandlerPerInsertionPoint = "scanPerInsertionPoint"
)

// Handlers lists the handler names in the order a run calls them.
var Handlers = []string{HandlerPerRequest, HandlerPerHost, HandlerPerInsertionPoint}

// handlerScopes maps each handler (and its scanTypes spelling) to the scan
// scope that selects it.
var handlerScopes = map[string]modkit.ScanScope{
	HandlerPerRequest:        modkit.ScanScopeRequest,
	HandlerPerHost:           modkit.ScanScopeHost,
	HandlerPerInsertionPoint: modkit.ScanScopeInsertionPoint,
}

// NormalizeHandler maps a handler name or its scanTypes spelling
// (per_request, per_host, per_insertion_point) to the handler name. ok is
// false for anything else.
func NormalizeHandler(name string) (string, bool) {
	n := strings.TrimSpace(name)
	switch strings.ToLower(n) {
	case "scanperrequest", "per_request", "request":
		return HandlerPerRequest, true
	case "scanperhost", "per_host", "host":
		return HandlerPerHost, true
	case "scanperinsertionpoint", "per_insertion_point", "insertion_point", "insertion":
		return HandlerPerInsertionPoint, true
	}
	return "", false
}

// ErrHook is returned by Load for a pre_hook or post_hook extension: a hook
// transforms requests or results and has no handler to run against a message.
var ErrHook = errors.New("hook extensions (pre_hook, post_hook) have no scan handler to run")

// LoadError reports an extension that did not load. Code is
// extension_load_failed.
type LoadError struct {
	Path     string
	Failures []jsext.LoadFailure
}

func (e *LoadError) Error() string {
	if len(e.Failures) == 0 {
		return fmt.Sprintf("extension %s loaded no module", e.Path)
	}
	parts := make([]string, 0, len(e.Failures))
	for _, f := range e.Failures {
		parts = append(parts, fmt.Sprintf("%s (%s): %v", f.Path, f.Stage, f.Err))
	}
	return fmt.Sprintf("extension failed to load: %s; see vigolium ext lint %s", strings.Join(parts, "; "), e.Path)
}

// Code reports the stable error code.
func (e *LoadError) Code() apicontract.ErrorCode { return apicontract.CodeExtensionLoadFailed }

// Options configures Load.
type Options struct {
	// HTTPClient carries the extension's traffic: vigolium.http.* and an active
	// module's own requests. Nil means an offline requester.
	HTTPClient *http.Requester
	// Repository backs vigolium.db / vigolium.ingest and ctx.record. Nil leaves
	// those namespaces unregistered. Pass a read-only handle to keep the run
	// from writing: record.annotate and friends then return false.
	Repository  *database.Repository
	ProjectUUID string
	// Base supplies variables, exec/sandbox settings and limits. Its directory
	// settings are ignored: only the named file is loaded.
	Base *config.ExtensionsConfig
}

// Extension is one loaded extension module, ready to Run.
type Extension struct {
	Path    string
	Active  modules.ActiveModule  // set for an active extension
	Passive modules.PassiveModule // set for a passive extension
	// Requester is what the module's traffic goes through; for an offline run
	// its RequestsRefused counts the blocked calls.
	Requester *http.Requester
}

// Module returns the loaded module, active or passive.
func (x *Extension) Module() modules.Module {
	if x.Active != nil {
		return x.Active
	}
	return x.Passive
}

// Kind is "active" or "passive".
func (x *Extension) Kind() string {
	if x.Active != nil {
		return "active"
	}
	return "passive"
}

// DeclaredHandlers lists the handlers the module's scanTypes select, in run
// order. A passive module has no scanPerInsertionPoint.
func (x *Extension) DeclaredHandlers() []string {
	scopes := x.Module().ScanScopes()
	var out []string
	for _, h := range Handlers {
		if h == HandlerPerInsertionPoint && x.Active == nil {
			continue
		}
		if scopes&handlerScopes[h] != 0 {
			out = append(out, h)
		}
	}
	return out
}

// Load loads the extension at path (.js, .ts or .vgm.yaml) through the scan
// loader and returns its single module. A load failure is a *LoadError; a hook
// extension wraps ErrHook.
func Load(path string, opts Options) (*Extension, error) {
	cfg := &config.ExtensionsConfig{}
	if opts.Base != nil {
		c := *opts.Base
		cfg = &c
	}
	// Exactly the named file: no extension directory, no other custom paths.
	cfg.Enabled = true
	cfg.ExtensionDir = ""
	cfg.CustomDir = []string{path}

	requester := opts.HTTPClient
	if requester == nil {
		requester = NewOfflineRequester()
	}
	engine, err := jsext.NewEngine(cfg, requester, &jsext.EngineOptions{
		Repository:  opts.Repository,
		ProjectUUID: opts.ProjectUUID,
	})
	if err != nil {
		return nil, &LoadError{Path: path, Failures: []jsext.LoadFailure{{Path: path, Stage: "unknown", Err: err}}}
	}
	if failures := engine.Failures(); len(failures) > 0 {
		return nil, &LoadError{Path: path, Failures: failures}
	}
	x := &Extension{Path: path, Requester: requester}
	active, passive := engine.ActiveModules(), engine.PassiveModules()
	switch {
	case len(active) == 1 && len(passive) == 0:
		x.Active = active[0]
	case len(passive) == 1 && len(active) == 0:
		x.Passive = passive[0]
	case len(engine.PreHooks()) > 0 || len(engine.PostHooks()) > 0:
		return nil, fmt.Errorf("%s: %w", path, ErrHook)
	default:
		return nil, &LoadError{Path: path}
	}
	return x, nil
}

// RunOptions selects what Run calls.
type RunOptions struct {
	// Handler is the one handler to call; empty calls every handler the
	// module's scanTypes declare.
	Handler string
	// Insertion selects one insertion point as TYPE:name (URL_PARAM:id), or
	// :name / name for any type. Empty runs scanPerInsertionPoint on every
	// point the module accepts. Implies Handler scanPerInsertionPoint.
	Insertion string
	// RecordUUID is what ctx.record.uuid reports (empty: no record).
	RecordUUID string
}

// CallError is one handler call that failed: the extension threw, timed out,
// or (for a YAML module) returned an error.
type CallError struct {
	Handler   string `json:"handler"`
	Insertion string `json:"insertion,omitempty"`
	Message   string `json:"message"`
}

// Outcome is what one Run produced.
type Outcome struct {
	ModuleID string
	// Handlers are the handlers that were called.
	Handlers []string
	// Calls counts handler invocations (one per insertion point for
	// scanPerInsertionPoint).
	Calls    int
	Results  []*output.ResultEvent
	Errors   []CallError
	Duration time.Duration
}

// UsageError is a RunOptions the module cannot satisfy (an unknown handler, a
// handler the module does not declare, an insertion point that is not there).
type UsageError struct{ msg string }

func (e *UsageError) Error() string { return e.msg }

func usageErrorf(format string, args ...any) error {
	return &UsageError{msg: fmt.Sprintf(format, args...)}
}

// Run calls the extension's handlers against rr and collects what they report.
// A handler that throws is an entry in Outcome.Errors, not an error: the run
// goes on to the next call. The error return is a *UsageError.
func (x *Extension) Run(rr *httpmsg.HttpRequestResponse, o RunOptions) (*Outcome, error) {
	handlers, err := x.selectHandlers(o)
	if err != nil {
		return nil, err
	}
	var points []httpmsg.InsertionPoint
	if slices.Contains(handlers, HandlerPerInsertionPoint) {
		points, err = x.insertionPoints(rr, o.Insertion)
		if err != nil {
			return nil, err
		}
	}

	mod := x.Module()
	out := &Outcome{ModuleID: mod.ID(), Handlers: handlers}
	scanCtx := &modkit.ScanContext{}
	if o.RecordUUID != "" {
		scanCtx.RequestUUIDResolver = fixedUUID(o.RecordUUID)
	}
	start := time.Now()
	call := func(handler, insertion string, fn func() ([]*output.ResultEvent, error)) {
		out.Calls++
		results, err := guarded(fn)
		if err != nil {
			out.Errors = append(out.Errors, CallError{Handler: handler, Insertion: insertion, Message: callErrorMessage(err)})
		}
		for _, r := range results {
			if r != nil {
				stampModuleDefaults(r, mod)
				out.Results = append(out.Results, r)
			}
		}
	}
	for _, h := range handlers {
		switch h {
		case HandlerPerRequest:
			call(h, "", func() ([]*output.ResultEvent, error) {
				if x.Active != nil {
					return x.Active.ScanPerRequest(rr, x.Requester, scanCtx)
				}
				return x.Passive.ScanPerRequest(rr, scanCtx)
			})
		case HandlerPerHost:
			call(h, "", func() ([]*output.ResultEvent, error) {
				if x.Active != nil {
					return x.Active.ScanPerHost(rr, x.Requester, scanCtx)
				}
				return x.Passive.ScanPerHost(rr, scanCtx)
			})
		case HandlerPerInsertionPoint:
			for _, ip := range points {
				call(h, pointLabel(ip), func() ([]*output.ResultEvent, error) {
					return x.Active.ScanPerInsertionPoint(rr, ip, x.Requester, scanCtx)
				})
			}
		}
	}
	out.Duration = time.Since(start)
	return out, nil
}

// selectHandlers resolves RunOptions to the handlers to call.
func (x *Extension) selectHandlers(o RunOptions) ([]string, error) {
	declared := x.DeclaredHandlers()
	handler := o.Handler
	if handler == "" && o.Insertion != "" {
		handler = HandlerPerInsertionPoint
	}
	if handler == "" {
		if len(declared) == 0 {
			return nil, usageErrorf("%s declares no handler this command can run", x.Module().ID())
		}
		return declared, nil
	}
	h, ok := NormalizeHandler(handler)
	if !ok {
		return nil, usageErrorf("unknown handler %q (want %s)", handler, strings.Join(Handlers, ", "))
	}
	if o.Insertion != "" && h != HandlerPerInsertionPoint {
		return nil, usageErrorf("--insertion selects a point for scanPerInsertionPoint, not %s", h)
	}
	if h == HandlerPerInsertionPoint && x.Active == nil {
		return nil, usageErrorf("%s is a passive extension: it has no scanPerInsertionPoint", x.Module().ID())
	}
	if !slices.Contains(declared, h) {
		return nil, usageErrorf("%s does not declare %s (its scanTypes select: %s)",
			x.Module().ID(), h, strings.Join(declared, ", "))
	}
	return []string{h}, nil
}

// insertionPoints returns the points scanPerInsertionPoint runs on: the one
// selector names, or every point the module accepts.
func (x *Extension) insertionPoints(rr *httpmsg.HttpRequestResponse, selector string) ([]httpmsg.InsertionPoint, error) {
	if rr == nil || rr.Request() == nil {
		return nil, usageErrorf("no request to build insertion points from")
	}
	all, err := httpmsg.CreateAllInsertionPoints(rr.Request().Raw(), true)
	if err != nil {
		return nil, usageErrorf("insertion points: %v", err)
	}
	allowed := x.Active.AllowedInsertionPointTypes()
	var accepted []httpmsg.InsertionPoint
	for _, ip := range all {
		if ip != nil && allowed.Contains(ip.Type()) {
			accepted = append(accepted, ip)
		}
	}
	if selector == "" {
		return accepted, nil
	}
	typeName, name, found := strings.Cut(selector, ":")
	if !found {
		typeName, name = "", selector
	}
	ip := httpmsg.FindInsertionPoint(accepted, typeName, name)
	if ip == nil {
		return nil, usageErrorf("insertion point %q not found; available: %s", selector, availablePoints(accepted))
	}
	return []httpmsg.InsertionPoint{ip}, nil
}

// availablePoints lists points as TYPE:name for an error message.
func availablePoints(ips []httpmsg.InsertionPoint) string {
	if len(ips) == 0 {
		return "(none)"
	}
	labels := make([]string, 0, len(ips))
	seen := map[string]bool{}
	for _, ip := range ips {
		l := pointLabel(ip)
		if !seen[l] {
			seen[l] = true
			labels = append(labels, l)
		}
	}
	sort.Strings(labels)
	return strings.Join(labels, ", ")
}

func pointLabel(ip httpmsg.InsertionPoint) string {
	return ip.Type().String() + ":" + ip.Name()
}

// guarded runs fn, turning a Go panic in a module into an error.
func guarded(fn func() ([]*output.ResultEvent, error)) (results []*output.ResultEvent, err error) {
	defer func() {
		if r := recover(); r != nil {
			results, err = nil, fmt.Errorf("panic: %v", r)
		}
	}()
	return fn()
}

// callErrorMessage is a handler error as its author wants to read it: the
// thrown value and the script position it came from, without sobek's Go-side
// stack ("JS error in <path>: GoError: … at github.com/…").
func callErrorMessage(err error) string {
	var ex *sobek.Exception
	if !errors.As(err, &ex) || ex.Value() == nil {
		msg, _, _ := strings.Cut(err.Error(), "\n")
		return msg
	}
	msg := ex.Value().String()
	if strings.Contains(err.Error(), "execution timeout") {
		msg = "timed out: " + msg
	}
	for _, f := range ex.Stack() {
		if p := f.Position(); f.SrcName() != "" && p.Line > 0 {
			msg += fmt.Sprintf(" (%s:%d:%d)", filepath.Base(f.SrcName()), p.Line, p.Column)
			break
		}
	}
	return msg
}

// stampModuleDefaults fills what the executor fills from the module before a
// result is stored, so a result reads here as it would in a scan.
func stampModuleDefaults(r *output.ResultEvent, m modules.Module) {
	r.ModuleID = m.ID()
	if r.Info.Name == "" {
		r.Info.Name = m.Name()
	}
	if r.Info.Severity == severity.Undefined {
		r.Info.Severity = m.Severity()
	}
	if r.Info.Confidence == severity.ConfidenceUndefined {
		r.Info.Confidence = m.Confidence()
	}
	if len(r.Info.Tags) == 0 {
		if tags := m.Tags(); len(tags) > 0 {
			r.Info.Tags = append([]string(nil), tags...)
		}
	}
	if r.Type == "" {
		r.Type = "http"
	}
	if r.Matched == "" && r.URL != "" {
		r.Matched = r.URL
	}
}

// fixedUUID resolves every request to one record UUID.
type fixedUUID string

func (u fixedUUID) ResolveRequestUUID(string) string { return string(u) }
