package core

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/zap"
)

// repoRiskScoreUpdater adapts *database.Repository to modkit.RiskScoreUpdater.
type repoRiskScoreUpdater struct {
	repo *database.Repository
}

func (u *repoRiskScoreUpdater) UpdateRiskScores(ctx context.Context, scores map[string]int) error {
	return u.repo.UpdateRiskScores(ctx, scores)
}

// repoSurfaceScoreUpdater adapts *database.Repository to modkit.SurfaceScoreUpdater.
type repoSurfaceScoreUpdater struct {
	repo *database.Repository
}

func (u *repoSurfaceScoreUpdater) UpdateSurfaceScores(ctx context.Context, scores map[string]int) error {
	return u.repo.UpdateSurfaceScores(ctx, scores)
}

// feedbackBlockTimeout bounds how long Feed will wait for room in a full feedback
// channel before dropping. Kept short so a producer (a worker mid-processResults)
// can never stall the pipeline for long — even in the pathological case where
// every worker feeds at once, the timeout guarantees forward progress — while
// still absorbing normal discovery bursts that a purely non-blocking send would
// drop outright.
const feedbackBlockTimeout = 100 * time.Millisecond

// executorFeeder implements modkit.RequestFeeder via a bounded-blocking send:
// discovered work is enqueued immediately when there's room, waited on briefly
// when the channel is momentarily full, and only dropped (counted + rate-limited
// warned) under sustained saturation.
type executorFeeder struct {
	ch       chan *work.WorkItem
	dropped  atomic.Int64
	lastWarn atomic.Int64
}

func (f *executorFeeder) Feed(rr *httpmsg.HttpRequestResponse) bool {
	item := work.NewWithModules(rr, nil)
	// Fast path: enqueue immediately when there's room.
	select {
	case f.ch <- item:
		return true
	default:
	}

	// Channel momentarily full: wait briefly for the feeder to drain rather than
	// dropping discovered URLs outright. Bounded by feedbackBlockTimeout so this
	// can never wedge the pipeline.
	timer := time.NewTimer(feedbackBlockTimeout)
	defer timer.Stop()
	select {
	case f.ch <- item:
		return true
	case <-timer.C:
		f.dropped.Add(1)
		// Rate-limited warning: log at most once every 5 seconds.
		now := time.Now().Unix()
		if last := f.lastWarn.Load(); now-last >= 5 {
			if f.lastWarn.CompareAndSwap(last, now) {
				zap.L().Warn("Feedback channel saturated, discovered URLs dropped",
					zap.Int64("total_dropped", f.dropped.Load()))
			}
		}
		return false
	}
}

// Dropped returns the total number of feedback items dropped due to channel capacity.
func (f *executorFeeder) Dropped() int64 {
	return f.dropped.Load()
}

// executorScopeExpander adapts *config.ScopeMatcher to modkit.ScopeExpander so
// modules (subdomain_harvest under --follow-subdomains) can add an exact
// discovered host to the scan's runtime scope allow-set.
type executorScopeExpander struct {
	matcher *config.ScopeMatcher
}

func (s *executorScopeExpander) AllowHost(host string) {
	if s.matcher != nil {
		s.matcher.AllowHost(host)
	}
}

// nopFeeder is the RequestFeeder used when ExecutorConfig.DisableFeedback is
// set: every Feed call returns false without doing any work. Lets modules
// that unconditionally call feeder.Feed(rr) keep working without forcing
// every caller to nil-check.
type nopFeeder struct{}

func (nopFeeder) Feed(*httpmsg.HttpRequestResponse) bool { return false }

var nopFeederInstance = nopFeeder{}

// executorIPProvider wraps the executor's LRU insertion point cache
// as a modkit.InsertionPointProvider so modules can reuse cached IPs.
type executorIPProvider struct {
	cache *InsertionPointCache
}

func (p *executorIPProvider) GetInsertionPoints(raw []byte, requestID string, includeNested bool) ([]httpmsg.InsertionPoint, error) {
	// A nil cache is handled by GetOrCompute's nil receiver.
	return p.cache.GetOrCompute(raw, requestID, includeNested)
}

// repoRemarksAnnotator adapts *database.Repository to modkit.RemarksAnnotator.
type repoRemarksAnnotator struct {
	repo *database.Repository
}

func (u *repoRemarksAnnotator) AppendRemarks(ctx context.Context, annotations map[string][]string) error {
	return u.repo.AppendRemarks(ctx, annotations)
}

// repoTechnologyAnnotator adapts *database.Repository to
// modkit.TechnologyAnnotator.
type repoTechnologyAnnotator struct {
	repo *database.Repository
}

func (u *repoTechnologyAnnotator) SetRecordTechnology(ctx context.Context, technology map[string][]string) error {
	return u.repo.SetRecordTechnology(ctx, technology)
}

// repoRecordResponseRewriter adapts *database.Repository to
// modkit.RecordResponseRewriter (used by the passive js-beautify module to
// overwrite a record's minified JS body with its beautified form).
type repoRecordResponseRewriter struct {
	repo *database.Repository
}

// repoDerivedArtifactWriter stores immutable analysis companions without
// modifying the raw HTTP record.
type repoDerivedArtifactWriter struct {
	repo *database.Repository
}

func (w *repoDerivedArtifactWriter) StoreDerivedArtifact(ctx context.Context, artifact *modkit.DerivedArtifact) error {
	if artifact == nil {
		return nil
	}
	metadata, err := json.Marshal(artifact.Metadata)
	if err != nil {
		return err
	}
	return w.repo.SaveAnalysisArtifactForRecord(ctx, &database.AnalysisArtifact{
		HTTPRecordUUID: artifact.RecordUUID,
		Kind:           artifact.Kind,
		Filename:       artifact.Filename,
		MediaType:      artifact.MediaType,
		SHA256:         artifact.SHA256,
		Content:        append([]byte(nil), artifact.Content...),
		Metadata:       string(metadata),
	})
}

func (u *repoRecordResponseRewriter) RewriteRecordResponse(ctx context.Context, uuid string, rawResponse []byte) error {
	return u.repo.OverwriteRecordResponseBody(ctx, uuid, rawResponse)
}

// executorScopeChecker adapts *config.ScopeMatcher to modkit.ScopeChecker so
// modules can ask whether a host is within the scan's scope (i.e. the target).
type executorScopeChecker struct {
	matcher *config.ScopeMatcher
}

func (s *executorScopeChecker) IsHostInScope(host string) bool {
	return s.matcher.HostInScope(host)
}
