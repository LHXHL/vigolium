package runner

import (
	"bytes"
	"context"
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
// of the fingerprint).

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

// sendFingerprintRound puts one round of every origin's probes on the wire
// through the executor and returns each origin's observations. A probe that
// produced no response is reported as an observation with Err set.
func (r *Runner) sendFingerprintRound(ctx context.Context, infra *phaseInfra, workers int,
	origins []fingerprintOrigin, plan func(fingerprintOrigin) []recon.ProbeRequest) (map[string][]recon.Observation, error) {
	type ref struct {
		origin string
		probe  recon.ProbeRequest
	}
	refs := map[*httpmsg.HttpRequestResponse]ref{}
	var items []*httpmsg.HttpRequestResponse
	for _, o := range origins {
		for _, p := range plan(o) {
			rr, err := buildFingerprintRequest(o.baseURL, p)
			if err != nil {
				zap.L().Debug("Fingerprint: unbuildable probe", zap.String("origin", o.baseURL), zap.String("path", p.Path), zap.Error(err))
				continue
			}
			refs[rr] = ref{origin: o.baseURL, probe: p}
			items = append(items, rr)
		}
	}
	if len(items) == 0 {
		return map[string][]recon.Observation{}, nil
	}

	var mu sync.Mutex
	got := map[*httpmsg.HttpRequestResponse]recon.Observation{}
	var writer *database.RecordWriter
	if r.repository != nil {
		writer = r.newScanRecordWriter()
	}
	cfg := core.ExecutorConfig{
		OnModuleError:    r.noteModuleError,
		Phase:            string(PhaseFingerprint),
		Workers:          workers,
		Services:         infra.svc,
		HTTPRequester:    infra.httpRequester,
		Repository:       r.repository,
		RecordWriter:     writer,
		ScanUUID:         infra.scanUUID,
		ProjectUUID:      r.options.ProjectUUID,
		ScopeMatcher:     infra.scopeMatcher,
		PauseCtrl:        r.pauseCtrl,
		OnTraffic:        r.makeOnTrafficVerbose("fingerprint"),
		RecordSource:     database.RecordSourceFingerprint,
		DisableFeedback:  true,
		KeepBlocked:      true,
		NoRedirects:      true,
		FetchStaticFiles: true,
		OnResponse: func(item *work.WorkItem, rr *httpmsg.HttpRequestResponse) {
			ref, ok := refs[item.Request]
			if !ok {
				return
			}
			obs := observationFrom(ref.probe, rr)
			mu.Lock()
			got[item.Request] = obs
			mu.Unlock()
		},
	}
	executor := core.NewExecutor(cfg, source.NewSliceSource(items, nil), nil, probePassiveModules())
	_, err := executor.Execute(ctx)
	r.currentPhase.Load().noteExecution(executor.Report())
	r.shutdownWriters("fingerprint", writer)
	if err != nil {
		return nil, err
	}

	out := make(map[string][]recon.Observation, len(origins))
	for _, rr := range items {
		ref := refs[rr]
		obs, ok := got[rr]
		if !ok {
			obs = recon.Observation{Req: ref.probe, URL: rr.Target(), Err: fmt.Errorf("no response (dead host, refused by scope or budget, or cancelled)")}
		}
		out[ref.origin] = append(out[ref.origin], obs)
	}
	return out, nil
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
		all := append(append([]recon.Observation{}, first[o.baseURL]...), second[o.baseURL]...)
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
	if r.repository != nil {
		saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), hostObservationSaveTimeout)
		if err := r.repository.SaveHostObservations(saveCtx, r.options.ProjectUUID, infra.scanUUID, inputs); err != nil {
			zap.L().Warn("Fingerprint: failed to persist host facts", zap.Error(err))
		}
		cancel()
	}

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
