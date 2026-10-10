package core

import (
	"context"
	"time"

	"github.com/sourcegraph/conc"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/storagesig"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/zap"
)

// feedItems pumps the input source into itemCh. It returns whether the source
// was EXHAUSTED — true only on io.EOF. Every other way out (cancellation, a
// deadline, a stop while paused, a blocked send) means items were left unread,
// which is the one fact the caller needs to know and could not previously learn:
// the function returned nothing, so a cancelled feed and a fully consumed one
// were the same event.
func (e *Executor) feedItems(ctx context.Context, itemCh chan<- *work.WorkItem) (exhausted bool) {
	// Sources report per-item failures by returning a non-EOF error from Next();
	// we log and skip the bad item, then keep reading. This must NOT abort the
	// feed: e.g. TargetSource advances its cursor before validating a URL, so a
	// malformed entry returns an error but the next call yields the next valid
	// target — bailing out here would silently drop the rest of the input.
	// Exhaustion is signalled by io.EOF (a source that can't make progress, like
	// a FileSource whose parse failed, reports its error once and then EOFs).
	//
	// The only hazard is a source that returns the same error on every call
	// without ever yielding an item or EOF; an unconditional retry would peg a
	// CPU. We guard against that with a small backoff once errors arrive
	// back-to-back with no item in between — a spin guard only, never a reason
	// to drop input. A source that interleaves errors with items resets the
	// streak and never pays the cost.
	const spinGuardThreshold = 4
	consecutiveErrors := 0
	for {
		select {
		case <-ctx.Done():
			return false
		default:
		}

		// Drain any pending feedback items (non-blocking) before pulling from source
		e.drainFeedback(ctx, itemCh)

		// Block feeding while paused
		if e.cfg.PauseCtrl != nil {
			if !e.cfg.PauseCtrl.WaitIfPaused(ctx) {
				return false
			}
		}

		item, err := e.source.Next(ctx)
		if err != nil {
			if source.IsEOF(err) {
				return true
			}
			if ctx.Err() != nil {
				return false
			}
			consecutiveErrors++
			zap.L().Warn("Error reading from source",
				zap.Error(err),
				zap.Int("consecutive_errors", consecutiveErrors))
			// Spin guard: only sleep once errors come back-to-back with no item
			// in between (a source stuck returning the same error). This never
			// fires for sources that keep making progress between errors.
			if consecutiveErrors >= spinGuardThreshold {
				select {
				case <-ctx.Done():
					return false
				case <-time.After(50 * time.Millisecond):
				}
			}
			continue
		}
		consecutiveErrors = 0

		if !e.sendItem(ctx, item, itemCh) {
			return false
		}
	}
}

// drainFeedback non-blocking drains all pending feedback items into itemCh.
func (e *Executor) drainFeedback(ctx context.Context, itemCh chan<- *work.WorkItem) {
	for {
		select {
		case fb := <-e.pool.feedbackCh:
			if !e.sendItem(ctx, fb, itemCh) {
				return
			}
		default:
			return
		}
	}
}

// sendItem applies scope/static filters and sends the item to itemCh.
// Returns false if context is cancelled.
func (e *Executor) sendItem(ctx context.Context, item *work.WorkItem, itemCh chan<- *work.WorkItem) bool {
	// Always filter static files before HTTP fetch — EXCEPT object-storage
	// assets, which are kept and recorded metadata-only (HEAD, body stripped)
	// so the CDN traversal modules can probe storage-fronted static URLs.
	if e.cfg.StaticFileMatcher != nil &&
		e.cfg.StaticFileMatcher.IsStaticFile(item.Request.Request().Path()) {
		if e.staticStorageCandidate(item.Request) {
			item.StaticMeta = true
		} else {
			item.Complete()
			return true
		}
	}

	// Pre-request scope check (host/path only — avoids HTTP call)
	if e.cfg.ScopeMatcher != nil && item.Request.Service() != nil {
		if !e.cfg.ScopeMatcher.InScopeRequest(
			item.Request.Service().Host(),
			item.Request.Request().Path(), "", "") {
			e.scopeRejected.Add(1)
			item.Complete()
			return true
		}
	}

	// Dead-host breaker: drop items for a quarantined host:port, with a count
	// (skipped_quarantined). Read-only — see skipQuarantined.
	if e.skipQuarantined(item.Request) {
		item.Complete()
		return true
	}

	select {
	case <-ctx.Done():
		return false
	case itemCh <- item:
		return true
	}
}

func (e *Executor) worker(ctx context.Context, _ int, itemCh <-chan *work.WorkItem) {
	for {
		// Block if paused, abort if context cancelled
		if e.cfg.PauseCtrl != nil {
			if !e.cfg.PauseCtrl.WaitIfPaused(ctx) {
				return
			}
		}

		select {
		case <-ctx.Done():
			return
		case item, ok := <-itemCh:
			if !ok {
				return
			}
			e.pool.inFlight.Add(1)
			if e.cfg.PauseCtrl != nil {
				e.cfg.PauseCtrl.AcquireWorker()
			}
			panicked := e.processItem(ctx, item)
			if e.cfg.PauseCtrl != nil {
				e.cfg.PauseCtrl.ReleaseWorker()
			}
			e.pool.inFlight.Add(-1)
			e.finishItem(ctx, item, panicked)
			if e.statsTracker != nil {
				e.statsTracker.Increment()
			}
		}
	}
}

// finishItem acknowledges an item only if it was actually processed.
//
// The worker's select can win a dequeue in the same instant the context is
// cancelled, and processItem's first act is to bail out on a cancelled context —
// so the item came off the queue, did no work, and was then acknowledged anyway.
// For a DB-backed source an ack is a durable cursor advance: the scan's cursor
// moved past records nothing ever looked at, and because a curtailed scan still
// recorded "completed", the next scan-on-receive run inherited that cursor and
// skipped them permanently. Withholding the ack is what makes those records get
// re-served.
//
// force is for a recovered panic: a poison item that keeps failing must still be
// acknowledged, or it comes back every run and the cursor never moves past it.
func (e *Executor) finishItem(ctx context.Context, item *work.WorkItem, force bool) {
	if !force && ctx.Err() != nil {
		e.unacked.Add(1)
		return
	}
	item.Complete()
}

// workerController monitors queue depth and scales workers up or down.
// Only active when AdaptiveWorkers is enabled.
func (e *Executor) workerController(ctx context.Context, itemCh chan *work.WorkItem, wg *conc.WaitGroup) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	nextID := e.cfg.Workers // start IDs after initial workers

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			queueDepth := len(itemCh)
			queueCap := cap(itemCh)
			active := int(e.pool.activeWorkers.Load())

			// Scale up: queue > 75% full and we have headroom
			if queueDepth > queueCap*3/4 && active < e.pool.maxWorkers {
				workerID := nextID
				nextID++
				e.pool.activeWorkers.Add(1)
				wg.Go(func() {
					e.worker(ctx, workerID, itemCh)
					e.pool.activeWorkers.Add(-1)
				})
				zap.L().Debug("Adaptive scaling: spawned worker",
					zap.Int("worker_id", workerID),
					zap.Int("active_workers", int(e.pool.activeWorkers.Load())))
			}

			// Note: scaling down is handled naturally — when itemCh is closed,
			// excess workers exit on their own. We don't preemptively kill workers
			// to avoid complexity of per-worker cancellation and potential data loss.
		}
	}
}

// processItem runs one work item through the fetch, passive and active stages.
// It returns whether a panic was recovered, which the caller needs in order to
// acknowledge the item anyway: a poison item that is never acknowledged is
// re-served on every subsequent run and freezes the cursor behind it.
func (e *Executor) processItem(ctx context.Context, item *work.WorkItem) (panicked bool) {
	// Registered first so it unwinds LAST, after the buffer-return defer below.
	defer e.recoverFromPanicInto("processItem", &panicked)

	// Bail out early if context is cancelled (graceful shutdown)
	select {
	case <-ctx.Done():
		return false
	default:
	}

	// Track pooled response buffer for deferred return.
	// Must be declared before the panic-recovery defer so it runs first (LIFO).
	//
	// guard withholds the buffer from the pool when a module call was abandoned
	// (per-module timeout or phase cancellation) and may still be reading it. See
	// responseBufferGuard.
	var pooledBuf []byte
	var guard responseBufferGuard
	ctx = withResponseBufferGuard(ctx, &guard)
	defer func() {
		if pooledBuf != nil && !guard.escaped.Load() {
			putResponseBuffer(pooledBuf)
		}
	}()

	req := item.Request
	enableModules := item.EnableModules

	zap.L().Debug("Processing item",
		zap.String("url", req.Target()),
		zap.Strings("enable_modules", enableModules))

	// Check context before expensive HTTP fetch
	select {
	case <-ctx.Done():
		return
	default:
	}

	var fetched baselineFetch
	var ok bool
	if item.StaticMeta {
		// Object-storage metadata items record the URL + headers (status,
		// content-type, content-length), never the (large/binary) object body:
		// a HEAD, falling back to a ranged GET for origins that reject HEAD.
		fetched, ok = e.fetchStaticMetaResponse(ctx, req)
	} else {
		fetched, ok = e.fetchBaseline(ctx, req)
	}
	if !ok {
		return
	}
	// Counted here rather than at the end of processItem: this is the exact point
	// where a server answered, and every later return in this function is a
	// policy decision about an answer we already have.
	e.responded.Add(1)
	// pooledBuf is ASSIGNED, never redeclared: the deferred putResponseBuffer
	// above closes over the outer variable, and a `:=` here would shadow it and
	// leak the buffer on every item.
	var httpResp *httpmsg.HttpResponse
	req, httpResp, pooledBuf = fetched.req, fetched.resp, fetched.pooledBuf
	redirectHops := fetched.hops

	// Learn object-storage-backed hosts from any storage-signalled response so
	// the static-file carve-out keeps sibling assets on the same host.
	if req.Service() != nil && storagesig.ResponseHasStorageSignal(httpResp) {
		e.markStorageHost(req.Service().Host())
	}

	// Static metadata items: keep only genuine storage assets, body stripped.
	if item.StaticMeta {
		if !storagesig.ResponseHasStorageSignal(httpResp) &&
			!storagesig.LooksLikeStorageObjectPath(req.Request().Path()) {
			return // storage hint did not pan out; drop without recording
		}
		httpResp.TruncateBody(0)
	}

	// Notify traffic callback
	if e.cfg.OnTraffic != nil {
		ct := getHeaderValue(httpResp.Headers(), "Content-Type")
		e.cfg.OnTraffic(req.Request().Method(), req.Target(), httpResp.StatusCode(), ct)
	}

	// Report a chain the transport stopped at an authentication wall. Read off
	// the stored 3xx rather than signalled out of CheckRedirect: the policy can
	// only answer with ErrUseLastResponse, and — decisively — the request
	// clusterer replays cached responses WITHOUT running CheckRedirect at all,
	// so anything recorded inside the policy would be missing on every cache
	// hit. Re-deriving is uniform across live and replayed responses.
	//
	// Status first: everything after it allocates (a header scan and a URL
	// rebuild), and the overwhelming majority of items are not redirects.
	if e.cfg.OnAuthWall != nil && httpmsg.IsRedirectStatus(httpResp.StatusCode()) {
		if wall, ok := http.StoppedAtAuthWall(req.Target(), httpResp.StatusCode(),
			getHeaderValue(httpResp.Headers(), "Location")); ok {
			e.cfg.OnAuthWall(req.Target(), wall)
		}
	}

	req, ok = e.applyPreHooks(req)
	if !ok {
		return
	}

	// Body size enforcement — truncate oversized bodies but defer drop/skip
	// decisions until after passive modules run (they are read-only).
	var bodySizeAction config.BodySizeAction
	if e.cfg.ScopeMatcher != nil {
		reqBodyLen := len(req.Request().Body())
		respBodyLen := len(httpResp.Body())
		var maxReq, maxResp int
		bodySizeAction, maxReq, maxResp = e.cfg.ScopeMatcher.CheckBodySize(reqBodyLen, respBodyLen)

		if bodySizeAction != config.BodySizeOK {
			if reqBodyLen > maxReq {
				req.Request().TruncateBody(maxReq)
				zap.L().Debug("Request body truncated",
					zap.String("url", req.Target()),
					zap.Int("original", reqBodyLen),
					zap.Int("truncated_to", maxReq))
			}
			if respBodyLen > maxResp {
				httpResp.TruncateBody(maxResp)
				zap.L().Debug("Response body truncated",
					zap.String("url", req.Target()),
					zap.Int("original", respBodyLen),
					zap.Int("truncated_to", maxResp))
			}
		}
	}

	// Module filter setup (needed by passive modules below)
	var filter moduleFilter
	if len(enableModules) == 0 {
		filter = allModulesFilter
	} else {
		filter = newModuleFilter(enableModules)
	}

	// Pre-register requestUUIDs for DB-sourced items so passive module
	// findings can link to the existing http_record instead of creating
	// duplicate "finding" records.
	if item.RecordUUID != "" && e.repo != nil {
		e.caches.requestUUIDs.Store(req.Request().ID(), item.RecordUUID)
	}

	// Pre-compute scope status before passive modules so scope-aware
	// passive modules can be skipped for out-of-scope items.
	inScope := true
	if e.cfg.ScopeMatcher != nil && req.Service() != nil {
		inScope = e.cfg.ScopeMatcher.InScopeBytes(
			req.Service().Host(),
			req.Request().Path(),
			httpResp.StatusCode(),
			getHeaderValue(req.Request().Headers(), "Content-Type"),
			getHeaderValue(httpResp.Headers(), "Content-Type"),
			req.Request().Raw(),
			httpResp.Body(),
		)
	}

	e.runPassiveStage(ctx, req, &filter, inScope)

	// Body size gate — drop/skip only affects active modules
	if bodySizeAction == config.BodySizeDrop {
		zap.L().Debug("Body size exceeded, dropping item (active scan skipped)",
			zap.String("url", req.Target()))
		return
	}
	if bodySizeAction == config.BodySizeSkipScan {
		e.saveToDatabase(ctx, item, req, redirectHops)
		return
	}
	skipActive := bodySizeAction == config.BodySizePassiveOnly

	if !e.persistAndCheckScope(ctx, item, req, inScope, redirectHops) {
		return
	}

	elig := computeEligibility(req)

	if !skipActive {
		e.runActiveStage(ctx, req, &filter, &elig)
	}
	return false
}
