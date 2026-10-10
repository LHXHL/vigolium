package core

import (
	"context"
	"errors"

	"github.com/vigolium/vigolium/pkg/core/egress"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/storagesig"
	"go.uber.org/zap"
)

// markStorageHost records that host fronts object storage.
func (e *Executor) markStorageHost(host string) {
	if host != "" {
		e.storageHosts.Add(host, struct{}{})
	}
}

// isLearnedStorageHost reports whether host was previously seen fronting
// object storage this scan.
func (e *Executor) isLearnedStorageHost(host string) bool {
	if host == "" {
		return false
	}
	return e.storageHosts.Contains(host)
}

// staticStorageCandidate reports whether a static-file request looks like an
// object-storage asset worth keeping (recorded metadata-only) rather than
// dropping: a /obj/<bucket>/<object> path shape, or a host already learned to
// front object storage.
func (e *Executor) staticStorageCandidate(rr *httpmsg.HttpRequestResponse) bool {
	if rr == nil || rr.Request() == nil {
		return false
	}
	if storagesig.LooksLikeStorageObjectPath(rr.Request().Path()) {
		return true
	}
	return rr.Service() != nil && e.isLearnedStorageHost(rr.Service().Host())
}

// fetchStaticMetaResponse fetches headers-only metadata for an object-storage
// static asset: a HEAD request, falling back to a ranged GET (Range: bytes=0-0)
// when the origin rejects HEAD (405/501). The full object body is never
// downloaded; callers still strip whatever minimal body returns.
func (e *Executor) fetchStaticMetaResponse(ctx context.Context, base *httpmsg.HttpRequestResponse) (baselineFetch, bool) {
	out, ok := e.fetchBaseline(ctx, staticMetaProbe(base, "HEAD", ""))
	if !ok || headRejectedStatus(out.resp.StatusCode()) {
		// Release the HEAD buffer before retrying with a ranged GET.
		//
		// This release needs no responseBufferGuard check, unlike processItem's:
		// the HEAD response never leaves this function — no module has run
		// against it and no record has been written from it — so nothing can
		// still be reading it. Any future code that hands this response to a
		// module or a writer before this point must take the guard into account.
		if out.pooledBuf != nil {
			putResponseBuffer(out.pooledBuf)
		}
		out, ok = e.fetchBaseline(ctx, staticMetaProbe(base, "GET", "bytes=0-0"))
	}
	// The point of a static-meta probe is one metadata row per object, not a
	// chain. Dropped explicitly rather than by a return value the caller happens
	// not to read — the hops are still WALKED above, which is the cost of saying
	// it here instead of in fetchBaseline.
	out.hops = nil
	return out, ok
}

// staticMetaProbe builds a header-only probe request from base: a method
// override plus an optional Range header. Returns base unchanged on parse error.
func staticMetaProbe(base *httpmsg.HttpRequestResponse, method, rangeHdr string) *httpmsg.HttpRequestResponse {
	raw := base.Request().Raw()
	if m, err := httpmsg.SetMethod(raw, method); err == nil {
		raw = m
	}
	if rangeHdr != "" {
		if h, err := httpmsg.AddHeader(raw, "Range", rangeHdr); err == nil {
			raw = h
		}
	}
	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return base
	}
	return req.WithService(base.Service())
}

// headRejectedStatus reports whether a status indicates the origin refused the
// HEAD method, so a ranged GET retry is warranted.
func headRejectedStatus(status int) bool {
	return status == 405 || status == 501
}

// baselineFetch is the outcome of fetching (or reusing) the response the rest
// of processItem scans.
type baselineFetch struct {
	req       *httpmsg.HttpRequestResponse
	resp      *httpmsg.HttpResponse
	pooledBuf []byte
	// hops are the intermediate redirect responses, oldest first, when
	// RecordRedirectChain is on and the request was redirected. Each is a
	// complete request/response pair ready to be written as its own record.
	hops []*httpmsg.HttpRequestResponse
}

func (e *Executor) fetchBaseline(ctx context.Context, req *httpmsg.HttpRequestResponse) (baselineFetch, bool) {
	if e.cfg.SkipBaseline && req.Response() != nil {
		return baselineFetch{req: req, resp: req.Response()}, true
	}

	// Bind the phase context so a cancelled scan / phase deadline / Ctrl-C aborts
	// the baseline fetch in flight. The context-less Execute would otherwise fall
	// back to context.Background() and keep hitting the target after the phase
	// asked every worker to stop.
	opts := http.Options{
		// The request clusterer serves repeats from a SNAPSHOT of the response,
		// reconstructed as a fresh single-response chain — so the redirect
		// linkage (resp.Request.Response) is gone and the hops would silently
		// vanish for every request after the first. Clustering is a
		// within-500ms duplicate-suppression optimization; hop recording is
		// evidence. When both are asked for, evidence wins.
		//
		// It costs nothing where this matters: a host sweep sends one request
		// per target, so there are no duplicates for the cache to collapse.
		NoClustering: e.cfg.RecordRedirectChain,
	}
	respChain, elapsed, err := e.httpClient.WithContext(ctx).Execute(req, opts)
	if err != nil {
		zap.L().Debug("Failed to fetch baseline response, skipping item",
			zap.String("url", req.Target()),
			zap.Error(err))
		// A cancelled phase fails every in-flight fetch; that says nothing
		// about the target, so it is not recorded as the target's failure.
		// A fetch the breaker refused (the host was quarantined after the
		// item was dispatched, or another request holds the half-open probe)
		// is a quarantine skip, not a transport failure of its own.
		// A fetch the request budget refused was never sent: the host used its
		// --max-requests-per-host (or the scan its --max-requests), which the
		// phase reports as a limit, not as the target failing to answer.
		switch {
		case errors.Is(err, hosterrors.ErrUnresponsiveHost):
			e.quarantine.add(httpmsg.HostPortKey(req))
		case errors.Is(err, egress.ErrBudgetExhausted):
		case ctx.Err() == nil:
			e.recordBaselineFailure(req.Target(), err)
		}
		return baselineFetch{}, false
	}

	if blockErr := infra.GetBlockDetectionValidator().Validate(respChain); blockErr != nil {
		respChain.Close()
		zap.L().Debug("Block detected, skipping item",
			zap.String("url", req.Target()),
			zap.Error(blockErr))
		if e.statsTracker != nil {
			e.statsTracker.IncrementBlocked()
		}
		return baselineFetch{}, false
	}

	// Compose headers+body directly into one pooled buffer. Using
	// FullResponseBytes() here would allocate a throwaway full-size copy that we
	// then copy *again* into the pooled buffer — two full-size allocations per
	// record on the hot path. HeadersBytes()/BodyBytes() alias the chain's own
	// buffers (valid until Close()), so a single splice into the pool suffices.
	headers := respChain.HeadersBytes()
	body := respChain.BodyBytes()
	rawResponseCopy := getResponseBuffer(len(headers) + len(body))
	copy(rawResponseCopy, headers)
	copy(rawResponseCopy[len(headers):], body)

	// elapsed is the requester's measurement of this send, so this is the one
	// place in the native-scan path that can populate response_time_ms at all.
	// Every other construction site rebuilds a response from stored bytes and
	// correctly leaves the duration at zero ("not measured").
	httpResp := httpmsg.NewHttpResponseWithDuration(rawResponseCopy, elapsed)
	out := baselineFetch{req: req.WithResponse(httpResp), resp: httpResp, pooledBuf: rawResponseCopy}

	// Redirect handling, in the only window where the chain is still intact and
	// the final response has already been copied out of it. Order matters twice
	// over: FinalRequestOf must run before RedirectChainHops (which rewinds the
	// chain), and both must run before Close (which reclaims the buffers).
	//
	// The re-pairing is UNCONDITIONAL. It used to be gated on
	// RecordRedirectChain — off for every phase but the probe — which left the
	// default path pairing the ORIGINAL request with the FINAL response: one
	// row whose URL named the target and whose body came from wherever the
	// chain ended. A scan of a host that 302s elsewhere filed the destination's
	// page, its technology and every passive finding under the target's own
	// URL, and the target's owner could not reproduce a line of it.
	//
	// Two things made that defensible before and no longer do. The record's
	// identity does change for a redirected target — but a row that misnames
	// its own origin has no identity worth preserving, and Target now carries
	// the submitted line, so nothing is lost by moving the URL to where the
	// bytes came from. And scope is matched on this request: leaving it at the
	// original host meant an out-of-scope destination was ingested and scanned
	// under an in-scope name.
	// ChainRelocated, not WasRedirected: the clusterer's reconstructed chain has
	// no resp.Request.Response, so the linkage test reports "not redirected" for
	// every cache hit — and clustering is ON for every phase that does not
	// record hops, which is all of them but the probe. It keeps the final hop's
	// request, so the destination URL survives; comparing it is what makes the
	// re-pairing work on the default path rather than only under --record-
	// redirect-chain.
	// URL() is memoized on the request, so this costs a map/pointer read rather
	// than a parse. An error here means the request URL never parsed, in which
	// case there is nothing to compare against and the linkage test decides.
	requestedURL, _ := req.Request().URL()
	relocated, linked := http.ChainRelocated(respChain, requestedURL.URL)
	if relocated {
		if finalReq := http.FinalRequestOf(respChain, httpResp); finalReq != nil {
			out.req = finalReq
		}
	}
	// The intermediate URLs are not lost by the swap: with hop recording on they
	// become their own records, and with it off they are dropped, which is the
	// setting's whole purpose — the terminal row still names its submitted
	// Target. Hop recording needs the real linkage rather than just a changed
	// URL, which is the second value ChainRelocated returns.
	if e.cfg.RecordRedirectChain && linked {
		out.hops = http.RedirectChainHops(respChain)
	}
	respChain.Close()

	return out, true
}

func (e *Executor) applyPreHooks(req *httpmsg.HttpRequestResponse) (*httpmsg.HttpRequestResponse, bool) {
	if e.hooks == nil {
		return req, true
	}

	hooked, err := e.hooks.RunPreHooks(req)
	if err != nil {
		zap.L().Debug("Pre-hook error, skipping item",
			zap.String("url", req.Target()), zap.Error(err))
		return nil, false
	}
	if hooked == nil {
		zap.L().Debug("Pre-hook filtered out item",
			zap.String("url", req.Target()))
		return nil, false
	}
	return hooked, true
}
