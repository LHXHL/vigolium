package verify

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core/egress"
	"github.com/vigolium/vigolium/pkg/core/network"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/jsext"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/types"
)

// The pieces `vigolium finding verify` and POST /api/findings/:id/verify share
// around Reconstruct and Run: the HTTP stack a re-run sends through, the
// extension modules an ext-* finding needs, and writing the verdict back.

// HTTPTimeout caps one request of a verification; RunOptions.Timeout bounds
// the whole run.
const HTTPTimeout = 15 * time.Second

// DefaultTimeout is the default bound on verifying one finding.
const DefaultTimeout = 2 * time.Minute

// HTTPConfig configures NewHTTPStack.
type HTTPConfig struct {
	ProxyURL    string
	Verbose     bool
	Debug       bool
	DumpTraffic bool
	// Timeout is the run's bound; one request gets the smaller of it and
	// HTTPTimeout.
	Timeout time.Duration
	// RateLimit is requests/second across the verification (0 = unlimited;
	// fractions allowed).
	RateLimit float64
}

// HTTPStack is the requester a verification runs modules with, behind an
// egress gate so the request count can be reported.
type HTTPStack struct {
	Requester *http.Requester
	Services  *services.Services
	cleanup   func()
}

// Close releases the stack's limiter, dedup manager and network reference.
func (s *HTTPStack) Close() {
	if s != nil && s.cleanup != nil {
		s.cleanup()
		s.cleanup = nil
	}
}

// NewHTTPStack builds the HTTP stack for a verification. It takes a reference
// on the process network dialer (network.Init) that Close returns.
func NewHTTPStack(cfg HTTPConfig) (*HTTPStack, error) {
	opts := types.DefaultOptions()
	opts.Timeout = HTTPTimeout
	if cfg.Timeout > 0 && cfg.Timeout < opts.Timeout {
		opts.Timeout = cfg.Timeout
	}
	opts.ProxyURL = cfg.ProxyURL
	opts.Verbose = cfg.Verbose
	opts.Debug = cfg.Debug
	opts.DumpTraffic = cfg.DumpTraffic
	if err := network.Init(opts); err != nil {
		return nil, fmt.Errorf("failed to initialize network: %w", err)
	}
	dedupMgr := dedup.NewManager()
	hostLimiter := hostlimit.NewHostRateLimiter(hostlimit.HostRateLimiterConfig{
		MaxPerHost:    opts.MaxPerHost,
		MaxEntries:    100,
		EvictAfter:    30 * time.Second,
		EvictInterval: 10 * time.Second,
	})
	svc := &services.Services{Options: opts, DedupManager: dedupMgr, HostLimiter: hostLimiter}
	if cfg.RateLimit > 0 {
		svc.RateLimiter = rate.NewLimiter(rate.Limit(cfg.RateLimit), 1)
	}
	svc.Egress = egress.New(egress.Config{Rate: svc.RateLimiter, Hosts: hostLimiter, Breaker: svc.HostErrors})
	cleanup := func() {
		dedupMgr.Close()
		_ = hostLimiter.Close()
		network.Close()
	}
	requester, err := http.NewRequester(opts, svc)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to create HTTP requester: %w", err)
	}
	return &HTTPStack{Requester: requester, Services: svc, cleanup: cleanup}, nil
}

// LoadExtensionModules loads the JS/YAML extensions cfg names and returns their
// modules by ID (active first when an ID is both).
func LoadExtensionModules(cfg *config.ExtensionsConfig, requester *http.Requester) (map[string]modules.Module, error) {
	engine, err := jsext.NewEngine(cfg, requester, &jsext.EngineOptions{})
	if err != nil {
		return nil, err
	}
	out := map[string]modules.Module{}
	for _, m := range engine.ActiveModules() {
		out[m.ID()] = m
	}
	for _, m := range engine.PassiveModules() {
		if _, dup := out[m.ID()]; !dup {
			out[m.ID()] = m
		}
	}
	return out, nil
}

// NeedsExtensions reports whether any finding was reported by an ext-* module.
func NeedsExtensions(findings ...*database.Finding) bool {
	for _, f := range findings {
		if f != nil && strings.HasPrefix(f.ModuleID, ExtensionModulePrefix) {
			return true
		}
	}
	return false
}

// ExtensionModulePrefix starts the ID of every JS/YAML extension module.
const ExtensionModulePrefix = "ext-"

// Resolver returns a ModuleResolver over the built-in registries plus ext,
// asking loadExt for the extension modules on the first ext-* lookup only.
// A nil loadExt (or one returning nil) leaves ext-* modules unresolved, which
// Reconstruct reports as unsupported.
func Resolver(loadExt func() map[string]modules.Module) ModuleResolver {
	var (
		once sync.Once
		ext  map[string]modules.Module
	)
	return func(id string) modules.Module {
		if !strings.HasPrefix(id, ExtensionModulePrefix) {
			return DefaultModuleResolver(id)
		}
		once.Do(func() {
			if loadExt != nil {
				ext = loadExt()
			}
		})
		return ext[id]
	}
}

// NeedsNetwork reports whether running p sends requests: an active module, or
// a passive one asked to refetch.
func (p *Plan) NeedsNetwork(refetch bool) bool {
	return p.Verdict == "" && (p.ModuleType == database.ModuleTypeActive || refetch)
}

// RecordOptions configures Record.
type RecordOptions struct {
	// Mark also moves the lifecycle status: not_reproduced → false_positive,
	// confirmed → confirmed, through the audited status path.
	Mark bool
	// Actor is recorded on a status change Mark makes.
	Actor string
	// ModuleVersion is stored with the verdict (the binary's version).
	ModuleVersion string
}

// MarkStatus is the lifecycle status a verdict moves a finding to under
// RecordOptions.Mark ("" = none).
func MarkStatus(verdict string) string {
	switch verdict {
	case database.VerdictNotReproduced:
		return database.StatusFalsePositive
	case database.VerdictConfirmed:
		return database.StatusConfirmed
	}
	return ""
}

// Record stores res's verdict on finding f (scoped to projectUUID) and, under
// opts.Mark, the status it implies. A failed write is reported in res.Reason;
// res.Written and res.Status say what landed.
func Record(ctx context.Context, repo *database.Repository, projectUUID string, f *database.Finding, res *Result, opts RecordOptions) {
	v := &database.FindingVerification{
		Verdict:       res.Verdict,
		At:            time.Now().UTC(),
		ModuleVersion: opts.ModuleVersion,
		ScanUUID:      f.ScanUUID,
		Reason:        res.Reason,
	}
	if err := repo.SetFindingVerification(ctx, projectUUID, f.ID, v); err != nil {
		res.Reason += "; verdict not stored: " + err.Error()
		return
	}
	res.Written = true
	if !opts.Mark {
		return
	}
	status := MarkStatus(res.Verdict)
	if status == "" {
		return
	}
	upd, err := repo.UpdateFindingStatusScoped(ctx, projectUUID, database.FindingStatusUpdate{
		IDs: []int64{f.ID}, Status: status, Note: "finding verify: " + res.Reason, Actor: opts.Actor,
	})
	if err != nil {
		res.Reason += "; status not set: " + err.Error()
	} else if len(upd.Changed) > 0 {
		res.Status = &upd.Changed[0]
	}
}

// DryRun returns the result a dry run reports for plan: the reconstruction,
// with nothing sent and nothing written.
func DryRun(plan *Plan, refetch bool) *Result {
	res := &Result{ID: plan.FindingID, FindingHash: plan.FindingHash, ModuleID: plan.ModuleID, Plan: plan,
		Verdict: plan.Verdict, Reason: plan.Reason}
	if plan.Verdict == "" {
		plan.Network = plan.ModuleType == database.ModuleTypeActive || refetch
		res.Reason = "dry run: nothing sent"
	}
	return res
}
