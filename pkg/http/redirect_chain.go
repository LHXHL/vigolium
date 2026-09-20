package http

import (
	"net/url"
	"slices"

	httpUtils "github.com/projectdiscovery/utils/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"go.uber.org/zap"
)

// maxRecordedRedirectHops bounds how many intermediate hops are materialized
// from one chain. The transport already caps redirects at MaxRedirects (default
// 10), so this is a backstop against a chain that somehow outgrew it, not the
// real policy — it exists so a pathological response can't turn one work item
// into an unbounded row count.
const maxRecordedRedirectHops = 20

// RedirectChainHops materializes every INTERMEDIATE hop of a followed redirect
// chain as its own request/response pair, oldest first. The final response is
// NOT included — its caller already owns that one.
//
// Returns nil when the request was not redirected.
//
// # This consumes the chain
//
// ResponseChain.Previous() rewinds the chain IN PLACE (resp = resp.Request.Response)
// and Fill() resets the shared header/body buffers to re-load the hop it landed
// on. So by the time this returns, the chain no longer refers to the final
// response and its buffers hold the OLDEST hop. Callers must have copied
// everything they need out of the chain first, and must treat the chain as
// write-off-and-Close afterwards. Getting that order wrong silently substitutes
// a 301's headers for the 200's.
//
// # Intermediate hops carry no body
//
// Go's client has already drained the bodies of the hops it followed, and
// respChain.Fill skips the body read entirely once `reloaded` is set. Each hop
// therefore yields its status line and headers — crucially including Location —
// and an empty body. That is the whole content of a redirect response in
// practice (RFC 9110 does not require one and servers rarely send one), but it
// does mean a hop record has content_length 0 and no body-derived signals.
//
// Hops carry no duration. The requester reports ONE elapsed time for the whole
// logical operation, which the caller attributes to the final response; there
// is no per-hop timing to recover, and dividing the total among hops would be
// inventing data. Zero here means unknown, per HttpResponse.Duration.
func RedirectChainHops(chain *httpUtils.ResponseChain) []*httpmsg.HttpRequestResponse {
	if chain == nil {
		return nil
	}

	var hops []*httpmsg.HttpRequestResponse
	for len(hops) < maxRecordedRedirectHops && chain.Previous() {
		if err := chain.Fill(); err != nil {
			// A hop we cannot re-read is dropped, not fatal: the final response
			// is already captured and the chain's remaining hops are still
			// walkable. Losing one intermediate 301 is strictly better than
			// failing the work item over it.
			zap.L().Debug("redirect chain: failed to fill hop", zap.Error(err))
			break
		}
		hop := hopFromChain(chain)
		if hop == nil {
			break
		}
		hops = append(hops, hop)
	}
	if len(hops) == 0 {
		return nil
	}

	// Previous() walks newest-to-oldest; records read far better oldest-first
	// (that is also the order they must be written in, so each hop's parent
	// UUID exists before its child needs it).
	slices.Reverse(hops)
	return hops
}

// hopFromChain snapshots the hop the chain is currently positioned on. Returns
// nil when the hop carries no usable request or response.
func hopFromChain(chain *httpUtils.ResponseChain) *httpmsg.HttpRequestResponse {
	// HeadersBytes aliases the chain's pooled buffer, which the NEXT Previous()/
	// Fill() overwrites and Close() reclaims — so this copy is mandatory, not an
	// optimization. Body is deliberately not appended: it is empty for a
	// rewound hop (see the doc comment), and asking for it would only add a
	// zero-length copy.
	raw := append([]byte(nil), chain.HeadersBytes()...)
	if len(raw) == 0 {
		return nil
	}
	return FinalRequestOf(chain, httpmsg.NewHttpResponse(raw))
}

// FinalRequestOf returns the request that produced the chain's CURRENT response,
// paired with resp, or nil when the chain carries no request.
//
// Redirect chains are why this exists. The executor pairs the ORIGINAL request
// with the FINAL response, so a followed chain produces a record whose URL says
// where the scan started and whose body came from wherever it ended up — the
// two halves of one row describing different servers. When hop recording is on,
// the caller re-pairs the final response with its own request through this, and
// the intermediate URLs survive as their own rows instead of being lost.
//
// Must be called BEFORE RedirectChainHops, which rewinds the chain.
func FinalRequestOf(chain *httpUtils.ResponseChain, resp *httpmsg.HttpResponse) *httpmsg.HttpRequestResponse {
	if chain == nil || resp == nil {
		return nil
	}
	stdReq := chain.Request()
	if stdReq == nil {
		return nil
	}
	// FromSentRequest, not FromStdRequest: the round trip is over, and
	// FromStdRequest's DumpRequestOut fails on a request whose context the
	// client already cancelled. See its doc comment.
	rr, err := httpmsg.FromSentRequest(stdReq)
	if err != nil {
		zap.L().Debug("redirect chain: failed to render request", zap.Error(err))
		return nil
	}
	return rr.WithResponse(resp)
}

// WasRedirected reports whether the chain's current response was reached by
// following at least one redirect. Cheap: it inspects the linked request/
// response pointers without touching buffers or rewinding anything.
func WasRedirected(chain *httpUtils.ResponseChain) bool {
	if chain == nil {
		return false
	}
	resp := chain.Response()
	return resp != nil && resp.Request != nil && resp.Request.Response != nil
}

// maxStoredChainRows bounds how many rows ONE chain contributes, counting the
// terminal response.
//
// Four covers every real chain measured: google.com settles in three
// (301 -> 302 -> 200), github.com in two. What it bounds is the pathological
// case — a chain that walks the full follow cap wrote ten rows, nine of them
// contentless, for one work item.
//
// This is a STORAGE cap, deliberately separate from the follow cap. Cutting the
// follow depth instead would lose the terminal response on a legitimate
// five-hop chain, which is the same data loss moved somewhere less visible.
const maxStoredChainRows = 4

// ChainRow is one redirect hop selected for storage.
type ChainRow struct {
	RR *httpmsg.HttpRequestResponse
	// Truncated marks a row whose destination is NOT the row after it: either
	// hops between them were dropped, or the chain stopped here. It is the one
	// bit that distinguishes "this 3xx pointed somewhere that never answered"
	// from "we stopped walking", which otherwise produce an identical row.
	Truncated bool
}

// ShapeRedirectChain selects which of a chain's intermediate hops to store.
//
// Two reductions, in this order, and the order matters: collapsing first means
// the cap spends its budget on hops that say something.
//
// # Canonical hops are dropped
//
// A hop whose destination is the same resource under its canonical spelling —
// a scheme upgrade, a trailing slash, www. gained or dropped — carries no
// information the destination row does not already carry. `curl -L
// ctdtoolkit.netflix.net` is the everyday shape: one 301 whose only content is
// "say it with https". Storing it produced a contentless row with no title, no
// technology and surface_score 0, sitting in the output next to rows that mean
// something, and it is why the row for a submitted target so often looked dead.
//
// Including the first hop. Keeping it was the obvious hedge — it is the only
// row carrying the submitted target's own status — but it is the wrong trade
// now that every row names its Target: the destination row already says which
// line produced it, so the 301 adds a contentless row and nothing else. A
// target whose only redirect is canonical therefore yields exactly one record,
// at the canonical URL, which is what an operator running `curl -L` sees.
//
// # Then the cap keeps the ends
//
// If more rows remain than the budget allows, the FIRST and the LAST survive
// and the middle goes: the first is the fact the caller asked for, the last is
// the fact they wanted. A cap that kept the first four and discarded the
// terminal response would be strictly worse than no cap at all.
//
// finalTarget is the URL of the response the caller pairs with these hops; it
// is what the last intermediate is classified against.
func ShapeRedirectChain(hops []*httpmsg.HttpRequestResponse, finalTarget string) []ChainRow {
	if len(hops) == 0 {
		return nil
	}

	// Target() is url.URL.String(), not a field read, and each hop is compared
	// as both "to" and "from". Resolve and parse once.
	targets := make([]string, len(hops))
	parsed := make([]*url.URL, len(hops))
	for i, hop := range hops {
		if hop == nil {
			continue
		}
		targets[i] = hop.Target()
		parsed[i], _ = url.Parse(targets[i])
	}
	finalURL, _ := url.Parse(finalTarget)

	kept := make([]*httpmsg.HttpRequestResponse, 0, len(hops))
	for i, hop := range hops {
		if hop == nil {
			continue
		}
		next := finalURL
		if i+1 < len(hops) {
			next = parsed[i+1]
		}
		if canonicalHop(parsed[i], next) {
			continue
		}
		kept = append(kept, hop)
	}
	if len(kept) == 0 {
		return nil
	}

	// The terminal response takes one of the rows, so the intermediates get the
	// rest. Keeping the head and the tail leaves exactly ONE discontinuity, and
	// it is always after the first row — which is why the flag below needs no
	// per-row bookkeeping to find it.
	budget := maxStoredChainRows - 1
	dropped := false
	if len(kept) > budget {
		kept = append(kept[:1], kept[len(kept)-(budget-1):]...)
		dropped = true
	}

	rows := make([]ChainRow, len(kept))
	for i, hop := range kept {
		rows[i] = ChainRow{RR: hop, Truncated: dropped && i == 0}
	}
	return rows
}

// ChainRelocated reports whether the exchange ended somewhere other than
// requested, and whether the chain still carries its redirect linkage.
//
// Two answers because the callers need different ones. Re-pairing the response
// with the request that produced it only needs "did we end up elsewhere";
// materializing the intermediate hops needs the linked responses themselves.
//
// The two can disagree, which is the whole reason this exists. The request
// clusterer caches a flattened snapshot and reconstructs a chain with no
// resp.Request.Response — deliberately, since retaining that pointer would pin
// every prior response and body for the cache entry's lifetime. The snapshot
// does keep the FINAL hop's request, so the destination URL survives even
// though the linkage does not.
//
// Compares URL fields rather than strings: this runs on every baseline fetch,
// and url.URL.String() allocates on both sides for an answer that is almost
// always "no".
func ChainRelocated(chain *httpUtils.ResponseChain, requested *url.URL) (relocated, linked bool) {
	if chain == nil {
		return false, false
	}
	linked = WasRedirected(chain)
	if linked {
		return true, true
	}
	stdReq := chain.Request()
	if stdReq == nil || stdReq.URL == nil || requested == nil {
		return false, false
	}
	got := stdReq.URL
	return got.Scheme != requested.Scheme ||
		got.Host != requested.Host ||
		got.Path != requested.Path ||
		got.RawQuery != requested.RawQuery, false
}
