package http

import (
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
