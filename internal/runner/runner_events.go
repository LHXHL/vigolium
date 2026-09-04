package runner

import (
	"context"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/knownissuescan"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/scanevents"
)

// progressInterval is how often a running phase reports phase.progress.
//
// Five seconds, because the counter this reports is the ONLY thing a consumer
// can read during a crawl that runs 5–15 minutes with no other output. Longer
// and a driver cannot distinguish "working" from "wedged" inside a reasonable
// patience window; shorter and a long scan's stream is mostly heartbeat.
const progressInterval = 5 * time.Second

// phaseTracker owns one phase's slice of the event stream: the started line, a
// progress heartbeat for as long as the phase runs, and the finished line with
// the phase's totals.
//
// The counters are read off the shared requester rather than accumulated here,
// so a phase that dispatches through a clone (every phase does) is counted the
// same way as one that does not, and nothing on the request hot path has to know
// the event stream exists.
type phaseTracker struct {
	phase     string
	start     time.Time
	requester *http.Requester
	baseSent  int64
	findings  atomic.Int64
	stop      chan struct{}
	stopped   chan struct{}
}

// beginPhase emits phase.started and starts the progress heartbeat. The returned
// tracker is always non-nil so the caller's finish call needs no guard; when the
// stream is off it does nothing at all.
func (r *Runner) beginPhase(ctx context.Context, phase string, requester *http.Requester) *phaseTracker {
	t := &phaseTracker{phase: phase, start: time.Now(), requester: requester}
	if !scanevents.On() {
		return t
	}
	t.baseSent = requester.RequestsSent()
	scanevents.Emit(scanevents.Event{Type: scanevents.TypePhaseStarted, Phase: phase})

	t.stop = make(chan struct{})
	t.stopped = make(chan struct{})
	go t.heartbeat(ctx)
	return t
}

func (t *phaseTracker) heartbeat(ctx context.Context) {
	defer close(t.stopped)
	ticker := time.NewTicker(progressInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			scanevents.Emit(scanevents.Event{
				Type:         scanevents.TypePhaseProgress,
				Phase:        t.phase,
				RequestsSent: scanevents.Int64(t.sentSoFar()),
				Findings:     scanevents.Int64(t.findings.Load()),
			})
		case <-t.stop:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (t *phaseTracker) sentSoFar() int64 {
	if t.requester == nil {
		return 0
	}
	return t.requester.RequestsSent() - t.baseSent
}

// recordFinding counts a finding against the running phase, so phase.finished
// reports what the phase actually produced rather than a scan-wide total.
func (t *phaseTracker) recordFinding() {
	if t == nil {
		return
	}
	t.findings.Add(1)
}

// finish emits phase.finished with the phase's totals and stops the heartbeat.
// status is "completed", or "failed" when err is non-nil; a phase stopped by the
// scan budget reports "curtailed" so a consumer does not read a time-boxed run
// as a clean one.
func (t *phaseTracker) finish(ctx context.Context, err error) {
	if t == nil || t.stop == nil {
		return
	}
	close(t.stop)
	<-t.stopped

	status := scanevents.StatusCompleted
	switch {
	case err != nil:
		status = scanevents.StatusFailed
	case ctx != nil && ctx.Err() != nil:
		status = scanevents.StatusCurtailed
	}
	ev := scanevents.Event{
		Type:         scanevents.TypePhaseFinished,
		Phase:        t.phase,
		Status:       status,
		DurationMS:   time.Since(t.start).Milliseconds(),
		RequestsSent: scanevents.Int64(t.sentSoFar()),
		Findings:     scanevents.Int64(t.findings.Load()),
	}
	if err != nil {
		ev.Message = err.Error()
	}
	scanevents.Emit(ev)
}

// attachEventObserver routes every finding the output writer emits into the
// machine event stream, and counts it against the phase that produced it. One
// call, one seam: the runner has ~six OnResult callbacks and the writer is the
// only thing all of them reach.
func (r *Runner) attachEventObserver() {
	if !scanevents.On() {
		return
	}
	sw, ok := r.output.(*output.StandardWriter)
	if !ok {
		return
	}
	prior := sw.OnEvent
	sw.OnEvent = func(ev *output.ResultEvent) {
		if prior != nil {
			prior(ev)
		}
		r.currentPhase.Load().recordFinding()
		emitFindingEvent(ev)
	}
}

// noteError reports a phase failure the scan SURVIVED. Most phases log and carry
// on, so their error never reaches the caller and never reaches phase.finished's
// status either — from the stream alone the phase looked fine. An `error` event
// is non-fatal by construction; a failure that ends the run rides on
// scan.finished instead.
//
// A method on the tracker rather than a free function taking a name: the tracker
// owns the CANONICAL phase id, and the eight call sites sit next to
// scanLogger.Error calls whose component labels are the short tags
// ("heuristics", "harvest", "respider"). Hand-typing the label at each site had
// already produced three phases that reported one spelling on phase.started and
// another on error, which silently breaks a consumer correlating the two.
func (t *phaseTracker) noteError(err error) {
	if t == nil || err == nil || !scanevents.On() {
		return
	}
	scanevents.Emit(scanevents.Event{
		Type:    scanevents.TypeError,
		Phase:   t.phase,
		Message: err.Error(),
	})
}

// emitBlockEvent mirrors the operator's [waf-block-detected] stderr line onto
// the machine stream. Both hang off the same notifier, so a consumer never has
// to scrape a rendered session log to recover a block — which is what it had to
// do before, at the cost of an N+1 subprocess walk per sweep.
func emitBlockEvent(n http.BlockNotice) {
	if !scanevents.On() {
		return
	}
	vendor := n.WAFType
	if vendor == "" || vendor == "generic" {
		vendor = "unknown"
	}
	scanevents.Emit(scanevents.Event{
		Type:       scanevents.TypeWAFBlock,
		Host:       n.Host,
		Vendor:     vendor,
		StatusCode: n.Status,
		Detail:     "edge is filtering scan traffic — results for this host may be incomplete",
	})
}

// emitPacingEvent mirrors [waf-pacing-armed] onto the machine stream, spelling
// out the concurrency drop so a consumer can attribute a slowdown to the pacing
// decision rather than to the target.
func emitPacingEvent(host, vendor string, from, to int) {
	if !scanevents.On() {
		return
	}
	if vendor == "" {
		vendor = "unknown"
	}
	scanevents.Emit(scanevents.Event{
		Type:            scanevents.TypeWAFPacing,
		Host:            host,
		Vendor:          vendor,
		ConcurrencyFrom: from,
		ConcurrencyTo:   to,
		Detail:          "proactive pacing: host is behind a CDN/WAF edge",
	})
}

// emitFindingEvent reports a finding as it is discovered. Deliberately a
// metadata line, not the finding: the stream is a progress channel, and the
// evidence lives in the database the consumer already has a handle to (the path
// is on scan.started). Carrying request/response bytes here would make the
// stream large enough that flushing per line stops being cheap.
func emitFindingEvent(result *output.ResultEvent) {
	if result == nil || !scanevents.On() {
		return
	}
	scanevents.Emit(scanevents.Event{
		Type:       scanevents.TypeFindingNew,
		Severity:   strings.ToLower(result.Info.Severity.String()),
		Confidence: strings.ToLower(result.Info.Confidence.String()),
		ModuleID:   result.ModuleID,
		URL:        result.URL,
		Host:       result.Host,
	})
}

// knownIssueScanEdge builds the pacing/detection hooks handed to the
// known-issue-scan phase. Both are backed by objects the rest of the scan
// already shares: the requester (whose block notifier and host-limiter feedback
// fire as a side effect of every probe) and the host limiter itself.
//
// Returns a zero Edge when there is no requester — the phase then behaves as it
// did before, which is the correct degradation for a caller that never built the
// shared infrastructure (a test, or an API path constructing the config by hand).
func (r *Runner) knownIssueScanEdge(infra *phaseInfra) knownissuescan.Edge {
	if infra == nil || infra.httpRequester == nil {
		return knownissuescan.Edge{}
	}
	requester := infra.httpRequester
	edge := knownissuescan.Edge{
		Probe: func(ctx context.Context, rawURL string) (bool, error) {
			return probeEdgeThroughRequester(ctx, requester, rawURL)
		},
	}
	if infra.hostLimiter != nil {
		limiter := infra.hostLimiter
		edge.HostLimit = limiter.CurrentLimit
	}
	return edge
}

// probeEdgeThroughRequester sends one GET to rawURL on the shared requester and
// reports whether the edge answered with a block.
//
// The classification is not done here: it is done inside the requester, by the
// same detector every other phase's traffic passes through, and its side effects
// (the one-time-per-host operator notice, the waf.block event, the limiter's
// WAF-auto-arm feedback) all fire from there. This function only needs to know
// whether the notifier considered the host blocked, which it learns by watching
// the requester's own classification via the response status and the block
// detector's verdict on the returned chain.
func probeEdgeThroughRequester(ctx context.Context, requester *http.Requester, rawURL string) (bool, error) {
	rr, err := httpmsg.GetRawRequestFromURL(rawURL)
	if err != nil {
		return false, err
	}
	chain, _, err := requester.ExecuteContext(ctx, rr, http.Options{})
	if err != nil {
		return false, err
	}
	return http.IsBlockedResponse(chain), nil
}
