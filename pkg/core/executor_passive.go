package core

import (
	"context"

	"github.com/sourcegraph/conc"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
)

// runPassivePerHostFiltered runs pre-filtered passive modules (CanProcess already checked).
func (e *Executor) runPassivePerHostFiltered(ctx context.Context, item *httpmsg.HttpRequestResponse, eligible []modules.PassiveModule) {
	origin := originKeyFromItem(item)

	for _, module := range eligible {
		// Claim this (module, origin) pair — skip if another worker already claimed
		// it. ContainsOrAdd is atomic (single lock) so two concurrent workers
		// can't both win the claim; ok==true means the pair was already claimed.
		claimKey := hostClaimKey{moduleID: module.ID(), origin: origin}
		if ok, _ := e.caches.perHostPassiveClaimed.ContainsOrAdd(claimKey, struct{}{}); ok {
			continue
		}

		results := e.runPassiveWithTimeout(
			ctx,
			func(runCtx context.Context) ([]*output.ResultEvent, error) {
				if contextual, ok := module.(modules.ContextualPassiveModule); ok {
					return contextual.ScanPerHostContext(runCtx, item, e.scanCtx)
				}
				return module.ScanPerHost(item, e.scanCtx)
			},
			module, item,
		)
		e.processResults(ctx, results, module, item)
	}
}

// runPassivePerRequestFiltered runs pre-filtered passive modules (CanProcess already checked).
func (e *Executor) runPassivePerRequestFiltered(ctx context.Context, item *httpmsg.HttpRequestResponse, eligible []modules.PassiveModule) {
	if len(eligible) == 0 {
		return
	}

	if e.cfg.ParallelPassive {
		var g conc.WaitGroup
		// sem bounds live passive goroutines across all record workers. nil (an
		// executor built without NewExecutor, e.g. in a unit test) falls back to the
		// old unbounded fan-out.
		sem := e.pool.passiveTaskSem
		for _, module := range eligible {
			mod := module
			// Acquire a global passive slot BEFORE spawning so the number of live
			// passive goroutines is bounded (not workers × modules). A cancelled
			// scan stops submitting.
			if sem != nil {
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					g.Wait()
					return
				}
			}
			g.Go(func() {
				if sem != nil {
					defer func() { <-sem }()
				}
				results := e.runPassiveWithTimeout(
					ctx,
					func(runCtx context.Context) ([]*output.ResultEvent, error) {
						if contextual, ok := mod.(modules.ContextualPassiveModule); ok {
							return contextual.ScanPerRequestContext(runCtx, item, e.scanCtx)
						}
						return mod.ScanPerRequest(item, e.scanCtx)
					},
					mod, item,
				)
				e.processResults(ctx, results, mod, item)
			})
		}
		g.Wait()
		return
	}

	for _, module := range eligible {
		results := e.runPassiveWithTimeout(
			ctx,
			func(runCtx context.Context) ([]*output.ResultEvent, error) {
				if contextual, ok := module.(modules.ContextualPassiveModule); ok {
					return contextual.ScanPerRequestContext(runCtx, item, e.scanCtx)
				}
				return module.ScanPerRequest(item, e.scanCtx)
			},
			module, item,
		)
		e.processResults(ctx, results, module, item)
	}
}
