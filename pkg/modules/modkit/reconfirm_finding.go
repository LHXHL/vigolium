package modkit

import (
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// ReconfirmFinding applies the BodyDifferentialConfirmable safety net to one
// candidate finding: findingRequest (the finding's payload-applied raw request)
// is replayed against item, the clean request the module scanned, through
// ConfirmBodyDifferential. item's captured response, when present, is folded
// into the baseline.
//
// It is the executor's reconfirmBodyDifferential decision (pkg/core calls it),
// so a module test can assert what the executor will do with its findings: Ran is
// false — keep the finding — when there is nothing to compare (no client, no
// item request, an empty finding request, or one byte-identical to the clean
// request, which is what a module reporting the unmodified request produces).
func ReconfirmFinding(client *http.Requester, item *httpmsg.HttpRequestResponse, findingRequest string) BodyDifferentialResult {
	if client == nil || item == nil || item.Request() == nil || findingRequest == "" {
		return BodyDifferentialResult{Ran: false, Reason: "not enough context to re-confirm"}
	}
	baselineRaw := item.Request().Raw()
	if findingRequest == string(baselineRaw) {
		return BodyDifferentialResult{Ran: false, Reason: "finding request carries no payload"}
	}
	cachedBody, cachedStatus := "", 0
	if item.HasResponse() && item.Response() != nil {
		cachedBody = string(item.Response().Raw())
		cachedStatus = item.Response().StatusCode()
	}
	return ConfirmBodyDifferential(client, item.Service(), []byte(findingRequest), baselineRaw,
		cachedBody, cachedStatus, ReconfirmConfig{NoRedirects: true})
}
