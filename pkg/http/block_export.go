package http

import (
	httpUtils "github.com/projectdiscovery/utils/http"
)

// IsBlockedResponse reports whether a response chain was classified as a WAF/CDN
// block (captcha, bot-detection, or challenge page).
//
// Exported for the one consumer that dispatches its own scan traffic and
// therefore cannot rely on the requester's internal per-response classification
// firing for it: known-issue-scan probes each target host through this requester
// before and during its nuclei run, and needs the verdict back rather than only
// its side effects. It runs the same classifier the hot path does, so a probe
// and a scan request can never disagree about what a block looks like.
func IsBlockedResponse(chain *httpUtils.ResponseChain) bool {
	return classifyWAFBlock(chain) != nil
}
