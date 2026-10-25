package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vigolium/vigolium/pkg/agent/recon"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/deparos/fingerprint"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/zap"
)

// The fingerprint phase answers "what is this origin" with a bounded set of
// reads — the base page and its icon, well-known paths, API-definition paths,
// a CORS preflight, OPTIONS, Host-header variants and three random paths — and
// stores the conclusion as a host fact, so a later session reads it with
// `vigolium hosts` instead of re-running curl.
//
// Every request goes through the scan executor: scope admission, the rate
// limit, the request budget, per-host slots and WAF pacing apply exactly as
// they do to any phase, and each request is stored as an http_record with
// source "fingerprint". The plan and the analysis are pkg/agent/recon's; this
// file only puts the plan on the wire and stores what came back.
//
// Redirects are not followed (a 301 from /robots.txt to /login is the answer),
// and a WAF block page is kept rather than dropped (which edge answers is part
// of the fingerprint). A read that fails in transport is asked once more, and
// every read still unanswered is named in the report's errors[] with the
// executor's reason for it, so an omitted path is never mistaken for a 404.

// fingerprintAutoLightThreshold is the target count above which the phase
// defaults to light depth: a long list is a triage pass, and standard depth is
// about sixty reads per origin.
const fingerprintAutoLightThreshold = 50

// fingerprintDepthFor is the depth the phase runs at: the operator's, or
// standard for a short target list and light for a long one.
func fingerprintDepthFor(opts *types.Options, targets int) recon.Depth {
	if opts != nil && strings.TrimSpace(opts.FingerprintDepth) != "" {
		if d, ok := recon.ParseDepth(opts.FingerprintDepth); ok {
			return d
		}
	}
	if targets > fingerprintAutoLightThreshold {
		return recon.DepthLight
	}
	return recon.DepthStandard
}

// fingerprintRequestsPerOrigin bounds one origin's reads at a depth: the first
// round, plus the icon, plus the vhost variants (standard and full) and the
// OPTIONS and source-map follow-ups (full), at recon's own bounds.
func fingerprintRequestsPerOrigin(d recon.Depth) (low, high int64) {
	first := int64(len(recon.Plan(d))) + 1
	switch d {
	case recon.DepthLight:
		return first, first
	case recon.DepthFull:
		return first, first + recon.MaxVHostVariants + recon.MaxOptionsPaths + recon.MaxSourceMaps
	}
	return first, first + recon.MaxVHostVariants
}

// fingerprintOrigin is one origin the phase fingerprints.
type fingerprintOrigin struct {
	baseURL string
	host    string
	port    int
}

// fingerprintOrigins reduces the resolved target list to distinct origins.
func fingerprintOrigins(targets []string) []fingerprintOrigin {
	var out []fingerprintOrigin
	for _, ep := range distinctSweepEndpoints(targets) {
		scheme := "http"
		if ep.https {
			scheme = "https"
		}
		out = append(out, fingerprintOrigin{baseURL: buildOriginURL(scheme, ep.host, ep.port), host: ep.host, port: ep.port})
	}
	return out
}

// buildFingerprintRequest renders one planned probe as a request against the
// origin. The Host header is the probe's override when it has one (a vhost
// variant); the connection always goes to the origin.
func buildFingerprintRequest(baseURL string, p recon.ProbeRequest) (*httpmsg.HttpRequestResponse, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	host := u.Host
	if p.Host != "" {
		host = p.Host
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\nAccept: */*\r\n", p.Method, p.Path, host)
	keys := make([]string, 0, len(p.Headers))
	for k := range p.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %s\r\n", k, p.Headers[k])
	}
	if p.Body != "" {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(p.Body))
	}
	b.WriteString("\r\n")
	b.WriteString(p.Body)
	return httpmsg.ParseRawRequestWithURL(b.String(), baseURL+p.Path)
}

// observationFrom copies one fetched response into a recon observation. The
// response buffer is pooled, so everything is copied out here.
func observationFrom(p recon.ProbeRequest, rr *httpmsg.HttpRequestResponse) recon.Observation {
	o := recon.Observation{Req: p, URL: rr.Target()}
	resp := rr.Response()
	if resp == nil {
		o.Err = fmt.Errorf("no response")
		return o
	}
	o.Status = resp.StatusCode()
	o.Headers = http.Header{}
	for _, h := range resp.Headers() {
		o.Headers.Add(h.Name, h.Value)
	}
	body := resp.Body()
	o.Body = string(body) // copies out of the pooled buffer
	if raw := resp.Raw(); len(raw) > 0 {
		if sp := bytes.IndexByte(raw, ' '); sp > 0 && sp < 16 {
			o.Proto = string(raw[:sp])
		}
	}
	if cl, err := strconv.Atoi(strings.TrimSpace(o.Headers.Get("Content-Length"))); err == nil && cl > len(body) {
		o.Truncated = true
	}
	return o
}

// fingerprintRetryBackoff is the pause before a round's network failures are
// asked again. Short: it lets a host that dropped connections under the
// round's burst drain, without stretching the pass.
const fingerprintRetryBackoff = 750 * time.Millisecond

// fingerprintRetryWorkers is the concurrency a round's retry runs at: two per
// origin that failed, never more than the round's own. A host that dropped
// reads under the round's concurrency is asked again at a pace it is far more
// likely to answer — the operator's pacing (rate limit, per-host slots, the
// adaptive limiter, which the requester feeds on every send) still applies.
func fingerprintRetryWorkers(workers, failingOrigins int) int {
	return max(1, min(workers, 2*failingOrigins))
}

// fingerprintBackoff waits d and reports whether ctx is still live.
func fingerprintBackoff(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// fingerprintProbeRef ties one executor item back to its origin and probe.
type fingerprintProbeRef struct {
	origin string
	probe  recon.ProbeRequest
}

// sendFingerprintRound puts one round of every origin's probes on the wire
// through the executor and returns each origin's observations. A probe that
// failed in transport is asked once more, after a short backoff and at a
// reduced concurrency; one that still has no answer is an observation with Err
// and ErrKind set, the kind classified from the executor's typed drop reason.
func (r *Runner) sendFingerprintRound(ctx context.Context, infra *phaseInfra, workers int,
	origins []fingerprintOrigin, plan func(fingerprintOrigin) []recon.ProbeRequest) (map[string][]recon.Observation, error) {
	refs := make([]fingerprintProbeRef, 0, len(origins))
	for _, o := range origins {
		for _, p := range plan(o) {
			refs = append(refs, fingerprintProbeRef{origin: o.baseURL, probe: p})
		}
	}
	if len(refs) == 0 {
		return map[string][]recon.Observation{}, nil
	}
	results, err := r.executeReads(ctx, infra, fingerprintReads, workers, refs)
	if err != nil {
		return nil, err
	}

	var retry []int
	failing := map[string]bool{}
	for i, obs := range results {
		if obs.Err != nil && obs.ErrKind == recon.ProbeErrNetwork {
			retry = append(retry, i)
			failing[refs[i].origin] = true
		}
	}
	if len(retry) > 0 && fingerprintBackoff(ctx, fingerprintRetryBackoff) {
		again := make([]fingerprintProbeRef, len(retry))
		for j, i := range retry {
			again[j] = refs[i]
		}
		zap.L().Debug("Fingerprint: retrying probes that failed in transport",
			zap.Int("probes", len(again)), zap.Int("origins", len(failing)))
		second, err := r.executeReads(ctx, infra, fingerprintReads, fingerprintRetryWorkers(workers, len(failing)), again)
		if err != nil {
			return nil, err
		}
		for j, i := range retry {
			// The retry's outcome is the probe's, unless the retry only says the
			// pass was cancelled: the first attempt's cause is the better fact.
			if second[j].Err == nil || second[j].ErrKind != recon.ProbeErrCancelled {
				results[i] = second[j]
			}
		}
	}

	out := make(map[string][]recon.Observation, len(origins))
	for i, ref := range refs {
		out[ref.origin] = append(out[ref.origin], results[i])
	}
	return out, nil
}

// readsConfig is how one batch of planned reads goes on the wire.
type readsConfig struct {
	phase NativePhase
	// source labels the stored records; "" stores none (the answers are only
	// read, e.g. the probe's icon, whose hash is the fact kept).
	source string
	// passive runs these modules on each answer.
	passive func() []modules.PassiveModule
	// keepBlocked keeps a WAF block page as the answer (which edge answers is
	// part of a fingerprint) instead of dropping the item.
	keepBlocked bool
}

// fingerprintReads stores every read as a fingerprint record and runs the
// probe's fingerprint modules on it.
var fingerprintReads = readsConfig{phase: PhaseFingerprint, source: database.RecordSourceFingerprint,
	passive: probePassiveModules, keepBlocked: true}

// executeReads sends refs through one executor run and returns one
// observation per ref, in order. A read the executor reported unanswered
// carries that reason's kind; one it never reported at all was cut off by
// cancellation (or, with the context still live, skipped).
func (r *Runner) executeReads(ctx context.Context, infra *phaseInfra, rc readsConfig, workers int,
	refs []fingerprintProbeRef) ([]recon.Observation, error) {
	results := make([]recon.Observation, len(refs))
	index := make(map[*httpmsg.HttpRequestResponse]int, len(refs))
	// settled tracks the DISPATCHED items only; an unbuildable ref never enters
	// index, so the sweep below never asks about it.
	settled := make([]bool, len(refs))
	items := make([]*httpmsg.HttpRequestResponse, 0, len(refs))
	for i, ref := range refs {
		rr, err := buildFingerprintRequest(ref.origin, ref.probe)
		if err != nil {
			zap.L().Debug("Unbuildable planned read", zap.String("phase", string(rc.phase)), zap.String("origin", ref.origin), zap.String("path", ref.probe.Path), zap.Error(err))
			results[i] = recon.Observation{Req: ref.probe, URL: ref.origin + ref.probe.Path,
				Err: fmt.Errorf("unbuildable request: %w", err), ErrKind: recon.ProbeErrSkipped}
			continue
		}
		index[rr] = i
		items = append(items, rr)
	}
	if len(items) == 0 {
		return results, nil
	}

	var mu sync.Mutex
	settle := func(item *work.WorkItem, obs func(ref fingerprintProbeRef) recon.Observation) {
		i, ok := index[item.Request]
		if !ok {
			return
		}
		o := obs(refs[i])
		mu.Lock()
		results[i], settled[i] = o, true
		mu.Unlock()
	}
	var writer *database.RecordWriter
	var repo *database.Repository
	if r.repository != nil && rc.source != "" {
		writer, repo = r.newScanRecordWriter(), r.repository
	}
	cfg := core.ExecutorConfig{
		OnModuleError: r.noteModuleError,
		Phase:         string(rc.phase),
		Workers:       workers,
		Services:      infra.svc,
		HTTPRequester: infra.httpRequester,
		Repository:    repo,
		RecordWriter:  writer,
		ScanUUID:      infra.scanUUID,
		ProjectUUID:   r.options.ProjectUUID,
		ScopeMatcher:  infra.scopeMatcher,
		PauseCtrl:     r.pauseCtrl,
		OnTraffic:     r.makeOnTrafficVerbose(string(rc.phase)),
		RecordSource:  rc.source,
		// A planned batch sends its reads and nothing else: no passive module
		// may re-inject a URL it extracted. This switch is that, and only that —
		// it does not touch the per-host limiter, which the requester feeds on
		// every send whatever the executor's feedback setting.
		DisableFeedback:  true,
		KeepBlocked:      rc.keepBlocked,
		NoRedirects:      true,
		FetchStaticFiles: true,
		OnResponse: func(item *work.WorkItem, rr *httpmsg.HttpRequestResponse) {
			settle(item, func(ref fingerprintProbeRef) recon.Observation { return observationFrom(ref.probe, rr) })
		},
		OnUnanswered: func(item *work.WorkItem, reason string, cause error) {
			settle(item, func(ref fingerprintProbeRef) recon.Observation {
				kind, err := fingerprintUnanswered(reason, cause)
				return recon.Observation{Req: ref.probe, URL: item.Request.Target(), Err: err, ErrKind: kind}
			})
		},
	}
	var passive []modules.PassiveModule
	if rc.passive != nil {
		passive = rc.passive()
	}
	executor := core.NewExecutor(cfg, source.NewSliceSource(items, nil), nil, passive)
	_, err := executor.Execute(ctx)
	r.currentPhase.Load().noteExecution(executor.Report())
	r.shutdownWriters(string(rc.phase), writer)
	if err != nil {
		return nil, err
	}
	for rr, i := range index {
		if settled[i] {
			continue
		}
		o := recon.Observation{Req: refs[i].probe, URL: rr.Target(),
			Err: errors.New("cancelled before an answer"), ErrKind: recon.ProbeErrCancelled}
		if ctx.Err() == nil {
			o.Err, o.ErrKind = errors.New("ended without an answer or a reason"), recon.ProbeErrSkipped
		}
		results[i] = o
	}
	return results, nil
}

// fingerprintUnanswered maps the executor's reason for an unanswered item to a
// probe error kind and the error the report shows.
func fingerprintUnanswered(reason string, cause error) (string, error) {
	kind, fallback := recon.ProbeErrSkipped, "refused before the send ("+reason+")"
	switch reason {
	case core.DropFetchError:
		kind, fallback = recon.ProbeErrNetwork, "no response"
	case core.DropQuarantined:
		kind, fallback = recon.ProbeErrNetwork, "host quarantined as unresponsive"
	case core.DropBudget:
		kind, fallback = recon.ProbeErrBudget, "request budget exhausted"
	case core.DropOutOfScope:
		kind, fallback = recon.ProbeErrScope, "refused by scope"
	case core.DropBlocked:
		kind, fallback = recon.ProbeErrBlocked, "blocked"
	}
	if cause != nil {
		return kind, cause
	}
	return kind, errors.New(fallback)
}

// notFoundBaselineFrom learns an origin's not-found baseline from its answers
// to the random paths.
func notFoundBaselineFrom(obs []recon.Observation) *database.NotFoundBaseline {
	var answered []recon.Observation
	for _, o := range obs {
		if o.Req.Kind == recon.KindNotFound && o.Err == nil {
			answered = append(answered, o)
		}
	}
	if len(answered) == 0 {
		return nil
	}
	first := answered[0]
	nf := &database.NotFoundBaseline{
		Status:       first.Status,
		Length:       len(first.Body),
		Words:        len(strings.Fields(first.Body)),
		Lines:        strings.Count(first.Body, "\n") + 1,
		ContentType:  first.Headers.Get("Content-Type"),
		Title:        recon.HTMLTitle(first.Body),
		Location:     first.Headers.Get("Location"),
		SoftNotFound: first.Status >= 200 && first.Status < 400,
	}
	if first.Body == "" {
		nf.Lines = 0
	}
	samples := make([]*fingerprint.Sample, 0, len(answered))
	for _, o := range answered {
		nf.Paths = append(nf.Paths, o.Req.Path)
		u, _ := url.Parse(o.URL)
		samples = append(samples, fingerprint.NewSampleFromParts(u, o.Status, o.Headers, []byte(o.Body)))
	}
	if sig, err := fingerprint.NewSignature(samples); err == nil {
		nf.Signature = sig.NamedStable()
	}
	return nf
}

func (r *Runner) runFingerprintPhase(ctx context.Context, infra *phaseInfra) error {
	started := time.Now()
	r.printPhaseStart("Fingerprint", "per-origin reads: well-known paths, favicon, CORS, OPTIONS, vhosts, not-found baseline")
	if len(r.options.Targets) == 0 {
		r.printPhaseDetail(terminal.Orange("no targets to fingerprint — pass -t/--target or -T/--target-file"))
		return nil
	}
	workers := r.options.Concurrency
	if workers <= 0 {
		workers = 10
	}
	depth := fingerprintDepthFor(r.options, len(r.options.Targets))
	low, high := fingerprintRequestsPerOrigin(depth)
	r.printPhaseDetail(fmt.Sprintf("Depth: %s (%d-%d reads per origin), redirects not followed, no state-changing methods",
		terminal.HiTeal(string(depth)), low, high))

	sweepTargets, unreachable := applyResolvedSchemes(r.options.Targets, r.resolveProbeSchemes(ctx, workers))
	r.prefetchProbeTargets(ctx, workers, infra.scanUUID, sweepTargets, true)
	origins := fingerprintOrigins(sweepTargets)
	if len(origins) == 0 {
		r.printPhaseComplete("Fingerprint", fmt.Sprintf("no origin answered (%d unreachable)", unreachable))
		return nil
	}

	first, err := r.sendFingerprintRound(ctx, infra, workers, origins, func(fingerprintOrigin) []recon.ProbeRequest {
		return recon.Plan(depth)
	})
	if err != nil {
		return err
	}
	second, err := r.sendFingerprintRound(ctx, infra, workers, origins, func(o fingerprintOrigin) []recon.ProbeRequest {
		return recon.PlanFollowUp(o.baseURL, depth, first[o.baseURL])
	})
	if err != nil {
		return err
	}

	inputs := make([]database.HostObservationInput, 0, len(origins))
	answered, soft := 0, 0
	for _, o := range origins {
		a, b := first[o.baseURL], second[o.baseURL]
		all := make([]recon.Observation, 0, len(a)+len(b))
		all = append(append(all, a...), b...)
		report := recon.Analyze(o.baseURL, all)
		report.Depth = string(depth)
		report.GeneratedAt = time.Now().UTC()
		report.Duration = time.Since(started)
		nf := notFoundBaselineFrom(all)
		if report.ProbeCount > report.ProbeErrors {
			answered++
		}
		if nf != nil && nf.SoftNotFound {
			soft++
		}
		inputs = append(inputs, database.HostObservationInput{
			Hostname: o.host, Port: o.port, Fingerprint: report, NotFound: nf, Complete: ctx.Err() == nil,
		})
	}
	r.persistHostObservations(ctx, infra.scanUUID, inputs, "Fingerprint: failed to persist host facts")

	summary := fmt.Sprintf("completed — %s of %s origins answered",
		terminal.Orange(strconv.Itoa(answered)), terminal.HiTeal(strconv.Itoa(len(origins))))
	if soft > 0 {
		summary += terminal.Gray(fmt.Sprintf(", %d answer 2xx/3xx to a missing path", soft))
	}
	r.printPhaseComplete("Fingerprint", summary+" in "+fmtDuration(time.Since(started)))
	if !r.options.Silent {
		r.printPhaseFeedback("Fingerprint", fmt.Sprintf("read it with %s",
			terminal.HiCyan("vigolium hosts --scan-uuid "+infra.scanUUID)))
	}
	return nil
}
