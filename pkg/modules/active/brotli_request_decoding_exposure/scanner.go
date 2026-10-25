package brotli_request_decoding_exposure

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	node2shellinfra "github.com/vigolium/vigolium/pkg/modules/infra/node2shell"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// The lane definition, the differential, the streams it sends and the
// decoder-naming heuristic are shared with the node2shell module, which runs
// the same gate before spending 22 MiB on the decoder's version. Aliased here
// so this file keeps reading in its own vocabulary.
const (
	probePath       = node2shellinfra.ProbePath
	unknownEncoding = node2shellinfra.UnknownEncoding
	decoyHeader     = node2shellinfra.DecoyHeader
	confirmRounds   = node2shellinfra.ConfirmRounds
)

// Module implements the Brotli request-decoding exposure check.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Brotli request-decoding exposure module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeHost|modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("brotli_request_decoding_exposure"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// IncludesBaseCanProcess returns false because this module uses a custom CanProcess.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// budget rations the origin's lanes. See node2shellinfra.Budget.
func (m *Module) budget(scanCtx *modkit.ScanContext) node2shellinfra.Budget {
	return node2shellinfra.NewBudget(m.ds.Get(scanCtx.DedupMgr()))
}

// CanProcess accepts any record with a request; probes are rebuilt from it.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil && ctx.Service() != nil
}

// ScanPerHost probes the origin's unrouted path, where an app-wide parser or a
// decoding proxy answers before any route. The executor runs it once per origin.
func (m *Module) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	return m.scan(ctx, httpClient, scanCtx, "POST", probePath, "application/json", node2shellinfra.LaneHost)
}

// ScanPerRequest probes up to maxRoutesPerOrigin recorded JSON routes, for a
// parser mounted on one route only.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	method := ctx.Request().Method()
	contentType := ctx.Request().Header("Content-Type")
	if !node2shellinfra.CarriesJSONBody(method, contentType) {
		return nil, nil
	}
	path := ctx.Request().Path()
	if !m.budget(scanCtx).TakeRoute(node2shellinfra.OriginOf(ctx), method, path) {
		return nil, nil
	}
	return m.scan(ctx, httpClient, scanCtx, method, path, contentType, node2shellinfra.LaneRoute)
}

// scan runs the differential on one method+path and records a hit so the
// origin is reported once.
func (m *Module) scan(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, scanCtx *modkit.ScanContext, method, path, contentType, lane string) ([]*output.ResultEvent, error) {
	origin := node2shellinfra.OriginOf(ctx)
	budget := m.budget(scanCtx)
	if budget.Settled(origin) {
		return nil, nil
	}
	p, ok := node2shellinfra.NewProber(ctx, httpClient, method, path, contentType)
	if !ok {
		return nil, nil
	}
	g, ok := node2shellinfra.RunGate(p.Send)
	if !ok {
		return nil, nil
	}
	budget.Settle(origin)
	return []*output.ResultEvent{buildResult(g, scanCtx, ctx, origin+path, lane)}, nil
}

// buildResult renders an opened gate as a candidate. The decoder's version is
// not observable from it — that is the node2shell module's job — so this stays
// an exposure record whatever the gate showed.
func buildResult(g node2shellinfra.Gate, scanCtx *modkit.ScanContext, ctx *httpmsg.HttpRequestResponse, target, lane string) *output.ResultEvent {
	decoder := node2shellinfra.LikelyDecoder(scanCtx, modkit.RegistryHostKey(ctx), g.Decoded.Header)
	return &output.ResultEvent{
		ModuleID:      ModuleID,
		RecordKind:    output.RecordKindCandidate,
		EvidenceGrade: output.EvidenceGradeDifferential,
		Host:          ctx.Service().Host(),
		URL:           target,
		Matched:       target,
		Request:       g.Decoded.Request,
		Response:      g.Decoded.Response,
		ExtractedResults: []string{
			"Lane: " + lane,
			"Likely decoder: " + decoder,
			fmt.Sprintf("Plain {} -> HTTP %d; malformed { -> HTTP %d", g.Empty.Sig.StatusCode, g.Malformed.Sig.StatusCode),
			fmt.Sprintf("Content-Encoding: %s {} -> HTTP %d (answered like plain {})", g.Encoding(), g.Decoded.Sig.StatusCode),
			fmt.Sprintf("Content-Encoding: %s { -> HTTP %d (answered like plain {)", g.Encoding(), g.DecodedMalformed.Sig.StatusCode),
			fmt.Sprintf("Encoded pair held over %d rounds", confirmRounds),
			fmt.Sprintf("Content-Encoding: %s, same bytes -> HTTP %d (not decoded)", unknownEncoding, g.Unknown.Sig.StatusCode),
			fmt.Sprintf("%s: <random>, plain {} -> HTTP %d (odd header ignored)", decoyHeader, g.Noise.Sig.StatusCode),
			fmt.Sprintf("%s: %s, same bytes, no Content-Encoding -> HTTP %d (not decoded)", decoyHeader, g.Encoding(), g.Misplaced.Sig.StatusCode),
			fmt.Sprintf("A stream the decoder refuses -> HTTP %d (a decode failure is observable here)", g.Failed.Sig.StatusCode),
			"Decoder version not observable here: run the node2shell module, or check it against the " + node2shellinfra.CVE + " fixed releases",
		},
		AdditionalEvidence: []string{
			"Unknown-encoding control request:\n" + g.Unknown.Request + "\n\nControl response:\n" + g.Unknown.Response,
		},
		Info: output.Info{
			Name:        "Potential Brotli request-body decoding (" + node2shellinfra.CVE + " exposure)",
			Description: fmt.Sprintf("The %s at %s decodes Content-Encoding: %s request bodies. If that decoder is an affected Brotli build, %s is reachable.", lane, target, g.Encoding(), node2shellinfra.CVE),
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        []string{"brotli", "cve-2026-111497", "node2shell"},
			Reference:   node2shellinfra.References,
		},
		Metadata: map[string]any{
			"lane":     lane,
			"encoding": g.Encoding(),
			"decoder":  decoder,
		},
	}
}
