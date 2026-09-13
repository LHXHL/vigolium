package runner

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
	vighttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/tlsprobe"
	"go.uber.org/zap"
)

// probePassiveTags selects the passive modules the probe phase runs.
//
// "fingerprint" is what makes the phase answer "what is this host running":
// those modules publish into the scan's TechRegistry, which is in turn the
// host-scoped signal in surface_scoring. Without them a probe would record a
// status code and nothing else — which is what `run discover` does today, since
// discovery.passive_module_tags has no default and the phase therefore runs
// ZERO passive modules.
//
// The set is deliberately narrow. "light" would have been the obvious pick and
// is wrong: 110 of the 117 passive modules carry it, so it is the whole
// registry under another name, and running all of it across thousands of hosts
// buries the sweep's actual output in findings. A probe is a triage pass; the
// modules that say "this is worth a real scan" earn their place, the rest do
// not.
var probePassiveTags = []string{"fingerprint"}

// probePhaseName is the canonical phase id, shared by the pace lookups and the
// NativePhase const so a rename cannot leave one of them behind.
const probePhaseName = string(PhaseProbe)

// probeExtraPassiveModuleIDs are passive modules the probe runs by ID because
// their tags do not describe them as fingerprinting. surface_scoring is tagged
// "behavior-analysis, light" — accurate, but it is precisely the per-record
// 0-100 ranking a sweep exists to produce, so it is named directly rather than
// by widening probePassiveTags into something that would drag in half the
// registry with it.
var probeExtraPassiveModuleIDs = []string{"surface-scoring"}

// runProbePhase sweeps the CLI target list: one request per target, passive
// modules only, no content discovery and no fuzzing.
//
// It is a sibling of the discovery phase rather than a mode of it, because the
// two differ in the thing that dominates their cost. Discovery builds a
// DeparosDiscoverySource that crawls and (on a discovery-only run) brute-forces
// paths per target; the probe issues exactly one request per target and is done.
// Pointing `run discover` at a few hundred hosts therefore spends its budget on
// the first handful — the probe spends one request each and reaches all of them.
func (r *Runner) runProbePhase(ctx context.Context, infra *phaseInfra) error {
	phaseStart := time.Now()

	if len(r.options.Targets) == 0 {
		r.printPhaseStart("Probe", "sweep targets for liveness, technology, and attack surface")
		r.printPhaseDetail(terminal.Orange("no targets to probe — pass -t/--target or -T/--target-file"))
		return nil
	}

	r.printPhaseStart("Probe", "sweep targets for liveness, technology, and attack surface")

	pace := r.probePace()
	r.printPhaseDetail(fmt.Sprintf("Speed: concurrency=%s, rate-limit=%s, max-per-host=%s",
		terminal.HiBlue(fmt.Sprintf("%d", pace.Concurrency)),
		terminal.HiBlue(fmt.Sprintf("%d", pace.RateLimit)),
		terminal.HiBlue(fmt.Sprintf("%d", pace.MaxPerHost))))

	passive := probePassiveModules()
	r.printPhaseDetail(fmt.Sprintf("Analysis: %s passive modules (tech fingerprinting + surface scoring), %s, redirects=%s",
		terminal.HiTeal(fmt.Sprintf("%d", len(passive))),
		terminal.HiTeal("no fuzzing"),
		terminal.HiTeal(r.probeRedirectDesc())))
	// Proactive edge pacing is off by default here (one request per host has no
	// burst to pre-empt). Stated rather than assumed: it is a safety default
	// being turned off, and an operator who wants it back needs to know it went.
	if r.options.NoWafPacing {
		r.printPhaseDetail(fmt.Sprintf("Pacing: %s %s",
			terminal.HiTeal("proactive WAF-edge pre-arm off"),
			terminal.Gray("(reactive back-off after a real block still applies; re-enable with --no-waf-pacing=false)")))
	}
	r.printTargetDetail(r.formatTargetCounts(ctx, len(r.options.Targets)))
	r.printVerboseTargets(r.options.Targets)

	// DNS prefetch, as its own bounded stage ahead of the HTTP sweep.
	//
	// On a sweep DNS is part of the ANSWER, not incidental metadata: "where does
	// this name point, and does it share infrastructure with the others" is half
	// of what a host list is being asked. The normal write-path resolver is
	// background/best-effort — correct there, because a blocking lookup would
	// stall the record writer for a full DNS timeout per dead host — but it means
	// the first record for each host is written before its answer arrives, which
	// on a one-request-per-host sweep is EVERY record. Resolving up front is what
	// makes the columns populated rather than empty.
	//
	// It is a separate stage rather than work folded into the request because
	// resolution and fetching have different natural concurrencies and different
	// failure modes: a host that does not resolve never needs a socket.
	r.prefetchProbeTargets(ctx, pace.Concurrency)

	// A dedicated writer so the phase's rows are flushed and counted on its own
	// boundary, mirroring the discovery phase. Closed before the processed-count
	// update so that count reflects rows that actually landed.
	var probeRecordWriter *database.RecordWriter
	if r.repository != nil {
		probeRecordWriter = database.NewRecordWriter(r.repository, database.RecordWriterConfig{})
	}

	executorCfg := core.ExecutorConfig{
		Workers:       pace.Concurrency,
		Services:      infra.svc,
		HTTPRequester: infra.httpRequester,
		Repository:    r.repository,
		RecordWriter:  probeRecordWriter,
		ScanUUID:      infra.scanUUID,
		ProjectUUID:   r.options.ProjectUUID,
		ScopeMatcher:  infra.scopeMatcher,
		PauseCtrl:     r.pauseCtrl,
		OnTraffic:     r.makeOnTrafficVerbose("probe"),
		// Label the rows so a sweep's output is separable from a real scan's in
		// the same project: `vigolium traffic --source probe`.
		RecordSource: database.RecordSourceProbe,
		// Every followed hop becomes its own row, chained by parent_uuid. On a
		// sweep this is the point rather than a detail: a host list is mostly
		// redirects, and "example.com answered 301 to www.example.com which
		// answered 200" is the finding.
		RecordRedirectChain: r.options.RecordRedirectChain,
		// The probe sends its own request per target and never re-injects, so
		// there is no feedback loop to drain.
		DisableFeedback: true,
		OnResult: func(result *output.ResultEvent) {
			if err := r.output.Write(result); err != nil {
				zap.L().Error("Failed to write result", zap.Error(err))
			}
		},
	}
	if pace.MaxDuration > 0 {
		executorCfg.MaxDuration = pace.MaxDuration
	}

	// The CLI target list directly — no deparos source, which is the whole
	// difference from the discovery phase.
	src := source.NewTargetSource(r.options.Targets, nil)

	executor := core.NewExecutor(executorCfg, src, nil, passive)
	_, err := executor.Execute(ctx)
	if probeRecordWriter != nil {
		probeRecordWriter.Close()
	}
	if err != nil {
		return err
	}

	if r.repository != nil && executor.Processed() > 0 {
		if err := r.repository.IncrementProcessedCount(ctx, infra.scanUUID, executor.Processed()); err != nil {
			zap.L().Warn("Probe: failed to increment processed count", zap.Error(err))
		}
	}

	elapsed := time.Since(phaseStart)
	r.printPhaseComplete("Probe", fmt.Sprintf("completed — %s of %s targets answered in %s",
		terminal.Orange(fmt.Sprintf("%d", executor.Processed())),
		terminal.HiTeal(fmt.Sprintf("%d", len(r.options.Targets))),
		terminal.HiPurple(fmtDuration(elapsed))))
	zap.L().Info("Probe: completed",
		zap.Int64("processed", executor.Processed()),
		zap.Int("targets", len(r.options.Targets)))

	if !r.options.Silent {
		r.printPhaseFeedback("Probe", fmt.Sprintf("rank the sweep with %s",
			terminal.HiCyan("vigolium traffic --source probe --sort surface_score")))
	}
	return nil
}

// probePace resolves the phase's speed dials.
//
// The three dials come from r.options (already fully resolved from the CLI) and
// are displaced ONLY by an explicit per-phase override. ResolvePhase cannot be
// used for them: it merges the per-phase section over the COMMON scanning_pace
// values and returns the result, so its Concurrency is non-zero even when no
// probe override exists — applying that would overwrite whatever -c the operator
// typed with the config file's common default. Reading the section directly is
// also what makes `--concurrency probe=200` work, since the pace flag writes the
// qualified value there.
//
// MaxDuration has no CLI equivalent on this phase, so it takes the merged value:
// a common scanning_pace.max_duration should bound the sweep exactly as it
// bounds every other phase.
func (r *Runner) probePace() config.ResolvedPhasePace {
	out := config.ResolvedPhasePace{
		Concurrency: r.options.Concurrency,
		RateLimit:   r.options.RateLimit,
		MaxPerHost:  r.options.MaxPerHost,
	}
	if r.settings == nil {
		return out
	}
	out.MaxDuration = r.settings.ScanningPace.ResolvePhase(probePhaseName).MaxDuration
	section := r.settings.ScanningPace.Section(probePhaseName)
	if section == nil {
		return out
	}
	if section.Concurrency > 0 {
		out.Concurrency = section.Concurrency
	}
	if section.RateLimit > 0 {
		out.RateLimit = section.RateLimit
	}
	if section.MaxPerHost > 0 {
		out.MaxPerHost = section.MaxPerHost
	}
	return out
}

// probeRedirectDesc renders the effective redirect policy for the phase header.
// It is shown unconditionally because "did this sweep follow the 301 or record
// it" changes what every row in the output means.
func (r *Runner) probeRedirectDesc() string {
	// ResolveRedirectMode is what NewRequester resolves the live policy with,
	// including the legacy DisableRedirects/FollowHostRedirects pair. Re-deriving
	// the default here would print "any" for a scan the requester is actually
	// running as same-host or off — and this line exists precisely because the
	// redirect policy changes what every row in the output means.
	mode := vighttp.ResolveRedirectMode(r.options)
	if r.options.RecordRedirectChain {
		return mode + " (hops recorded)"
	}
	return mode
}

// probePassiveModules resolves the phase's passive module set: everything tagged
// for fingerprinting, plus the explicitly named extras. No dedup needed —
// GetPassiveModulesByIDs builds a set from the ids and walks the registry once,
// so a repeated id cannot yield a repeated module.
func probePassiveModules() []modules.PassiveModule {
	return modules.GetPassiveModulesByIDs(
		append(modules.ResolveModuleTags(probePassiveTags), probeExtraPassiveModuleIDs...))
}

// probeDNSConcurrency bounds the prefetch stage. Resolution is cheaper and more
// parallel than an HTTP round trip, so it runs wider than the request
// concurrency — but nowhere near unbounded: the pure-Go resolver still costs a
// goroutine and a socket per lookup, and a local recursive resolver starts
// dropping UDP under load, which presents as multi-second timeouts rather than
// as an error. Capped so a huge target list cannot turn the prefetch into the
// slowest part of the sweep.
const (
	probeDNSConcurrencyFactor = 4
	probeDNSConcurrencyMax    = 128
)

// sweepEndpoint is one distinct endpoint to prefetch: a hostname, plus the port
// and scheme the sweep will contact it on.
type sweepEndpoint struct {
	host  string
	port  int
	https bool
}

// prefetchProbeTargets resolves DNS for every target hostname — and, under
// --tls-probe, completes a TLS handshake against every HTTPS endpoint — before
// the sweep sends its first request.
//
// One pass over the target list rather than a stage each, because both are
// per-host facts keyed the same way and both feed the same serialization-time
// attachment. Splitting them would walk the list twice and pay two goroutine
// pools to answer two questions about the same endpoint.
//
// Best-effort by construction: a DNS failure leaves that record's DNS fields
// empty ("did not resolve"), and a failed handshake is itself reported
// (ProbeStatus false) rather than dropped — "this host does not speak TLS" is an
// answer a sweep wants. Honours ctx so a cancelled scan stops prefetching
// instead of walking the whole list.
func (r *Runner) prefetchProbeTargets(ctx context.Context, requestConcurrency int) {
	targets := r.distinctSweepEndpoints()
	if len(targets) == 0 {
		return
	}
	tlsProbe := r.options.TLSProbe

	workers := min(max(requestConcurrency, 1)*probeDNSConcurrencyFactor, probeDNSConcurrencyMax)
	workers = min(workers, len(targets))

	start := time.Now()
	var resolved, tlsOK atomic.Int64
	queue := make(chan sweepEndpoint)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range queue {
				if v4, v6 := database.ResolveHostnameNow(t.host); len(v4)+len(v6) > 0 {
					resolved.Add(1)
				}
				// Only HTTPS endpoints are handshaked: a TLS probe against a
				// plaintext port is a guaranteed timeout, and on a large sweep
				// those timeouts would dominate the stage.
				if tlsProbe && t.https {
					if info := tlsprobe.Probe(ctx, t.host, t.port, tlsprobe.DefaultTimeout); info != nil && info.ProbeStatus {
						tlsOK.Add(1)
					}
				}
			}
		}()
	}
	for _, t := range targets {
		select {
		case <-ctx.Done():
			close(queue)
			wg.Wait()
			return
		case queue <- t:
		}
	}
	close(queue)
	wg.Wait()

	detail := fmt.Sprintf("DNS: resolved %s of %s hostname(s)",
		terminal.Orange(fmt.Sprintf("%d", resolved.Load())),
		terminal.HiTeal(fmt.Sprintf("%d", len(targets))))
	if tlsProbe {
		detail += fmt.Sprintf(" | TLS: %s handshake(s) completed",
			terminal.Orange(fmt.Sprintf("%d", tlsOK.Load())))
	}
	r.printPhaseDetail(detail + " in " + terminal.HiPurple(fmtDuration(time.Since(start))))
}

// distinctSweepEndpoints reduces the CLI target list to one entry per
// host:port, preserving order. A sweep routinely carries several URLs on one
// host; resolving or handshaking it once per URL would multiply the stage's
// cost for an answer that cannot differ.
//
// Parsing goes through hostAndPort (port_sweep.go) rather than a second URL
// parser: that one prefixes a missing scheme before parsing, and without the
// prefix a schemeless `example.com:8443` parses as Scheme="example.com" with no
// port — so the endpoint would be resolved and handshaked on 443 while the
// port-sweep phase read the same line as 8443. One parser, one answer.
func (r *Runner) distinctSweepEndpoints() []sweepEndpoint {
	out := make([]sweepEndpoint, 0, len(r.options.Targets))
	seen := make(map[string]struct{}, len(r.options.Targets))
	for _, raw := range r.options.Targets {
		host, portStr := hostAndPort(raw)
		if host == "" {
			continue
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 {
			continue
		}
		key := host + ":" + portStr
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		// hostAndPort defaults a schemeless target to https, so "is this TLS"
		// is answered by the port it resolved rather than by re-reading the
		// scheme. 80 is the only plaintext default it produces.
		out = append(out, sweepEndpoint{host: host, port: port, https: port != 80})
	}
	return out
}
