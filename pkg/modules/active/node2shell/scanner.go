package node2shell

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	node2shellinfra "github.com/vigolium/vigolium/pkg/modules/infra/node2shell"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// The lane definition is shared with brotli_request_decoding_exposure, which
// runs the same gate: the two modules must look for the decoder in the same
// places, or the cheap surface record and the expensive version record
// disagree about where it is.
const (
	probePath = node2shellinfra.ProbePath
)

// refusedBeforeDecode are refusals an edge sends off the advertised
// Content-Length or the framing, before anything decoded the body. They make
// the probe inconclusive rather than negative: the decoder was never reached.
//
// Deliberately narrow. 400 and 422 are NOT here — on a path that reads JSON
// they are the malformed class the oracle compares against, and treating them
// as a refusal would discard the very answer the probe is looking for.
var refusedBeforeDecode = map[int]bool{
	411: true, 413: true, 414: true, 417: true, 429: true, 431: true,
}

// probeSlots bounds how many origins send the multi-MiB streams at once. Each
// in-flight probe holds the stream, the raw request built around it and the
// parsed copy — roughly 70 MiB for one 22 MiB body — so an unbounded fan-out
// over many decoding hosts would be measured in gigabytes.
var probeSlots = make(chan struct{}, 1)

// Module implements the node2shell Brotli decoder-version probe.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new node2shell module.
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
		ds: dedup.LazyDiskSet("node2shell"),
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
// decoding proxy answers before any route.
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

// scan runs the cheap decode gate on one method+path and, only if it opens,
// spends the origin's single 44 MiB probe budget on the version oracle.
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

	// Ten sub-32-byte requests that answer "does anything here decode plain
	// Brotli request bodies at all". The Assetnote scanner skips this and fires
	// its 22 MiB probe at every host; on everything that does not decode br,
	// that upload buys nothing.
	g, ok := node2shellinfra.RunGateFor(p.Send, node2shellinfra.BrotliOnly())
	if !ok {
		return nil, nil
	}

	// Claim the origin before the expensive stage so a second record racing
	// through the gate cannot double-spend it.
	if !budget.Settle(origin) {
		return nil, nil
	}
	probeSlots <- struct{}{}
	defer func() { <-probeSlots }()

	v, ok := confirm(p, g)
	if !ok {
		return nil, nil
	}
	// Last gate, paid only by a host that already produced a candidate: an
	// endpoint whose pool answers one unmodified request with different pages
	// makes every pairwise comparison above a coin flip. Memoized per record and
	// shared with the other differential modules, and it fails open.
	if modkit.EndpointVolatile(scanCtx, ctx, httpClient) {
		return nil, nil
	}
	return []*output.ResultEvent{buildResult(v, g, scanCtx, ctx, origin+path, lane)}, nil
}

// probeRounds is how many times the probe must reach the route's {} class,
// with the three learned classes re-proven in between, before the decoder is
// called a lead.
//
// One match is a coin flip on a host whose pool mixes patched and unpatched
// backends: the probe lands on an affected worker, the twin lands on any
// worker and fails to decode either way, and the pair reads as a clean
// positive. Two matches separated by a re-verification do not survive that —
// the rotation has to deliver the same answer to both rounds AND leave all
// three tiny classes intact across them.
const probeRounds = 2

// verdict is a completed version oracle: the twin and the last probe exchange
// that produced it, plus what the stability control said afterwards.
type verdict struct {
	twin, probe node2shellinfra.Exchange
	// stopped records that the route no longer answered after the last probe.
	stopped bool
}

// confirm runs the multi-MiB streams against a path the gate has already shown
// decodes plain Brotli, and reports whether the decoder looks unpatched.
//
// The probe goes first and the twin second, which is both cheaper and gentler
// than the other order. A decoder with the fix — the overwhelming majority —
// refuses the probe, lands in the decode-failure class and ends the stage after
// ONE 22 MiB body instead of two; and those hosts never receive the twin at
// all. The twin is only worth its bandwidth once there is something to explain
// away.
//
//   - each round's probe must land in the route's {} class. In the
//     decode-failure class the decoder refused it and carries the fix: the
//     common, correct outcome, and nothing is reported. In neither class
//     nothing is attributable.
//   - the twin must land in the DECODE-FAILURE class the gate learned from a
//     one-byte bad stream. That is the proof the decoder sees a body this size
//     and refuses it on its merits. If the twin lands in the {} class instead, a
//     body that size is being dropped or truncated into an empty document and
//     the probe's match was never about the decode. If it lands in neither (a
//     413, a proxy error), the decoder was not reached.
//   - between rounds all three tiny classes are re-proven, so a probe is never
//     scored against a snapshot the endpoint has since moved away from.
//   - the tiny valid control is re-sent at the end. The route still answering
//     as before is the clean case; a route that stops answering is reported
//     with that said plainly, because the probe already matched and an operator
//     needs to know the host may have been affected by it.
//
// Cost: one probe on a patched host, plus a twin and a second probe only on a
// host that already looks affected.
func confirm(p *node2shellinfra.Prober, g node2shellinfra.Gate) (verdict, bool) {
	// The probe is a bare Brotli document, so it can only be delivered under
	// plain br. The gate was restricted to br for that reason; this is the
	// belt-and-braces check, because sending it under a stacked encoding would
	// come back negative on every host and read as "patched".
	if g.Encoding() != node2shellinfra.BrotliEncoding {
		return verdict{}, false
	}
	var ok bool

	var v verdict
	// Round one. A patched decoder refuses here and the stage ends.
	if v.probe, ok = sendStream(p, g, node2shellinfra.ProbeStream(), g.Empty); !ok {
		return verdict{}, false
	}
	// The size control, sent once: what it controls for — the size of the body
	// — does not change between rounds.
	if v.twin, ok = sendStream(p, g, node2shellinfra.TwinStream(), g.Failed); !ok {
		return verdict{}, false
	}
	for range probeRounds - 1 {
		if !node2shellinfra.Reverify(p.Send, g) {
			return verdict{}, false
		}
		if v.probe, ok = sendStream(p, g, node2shellinfra.ProbeStream(), g.Empty); !ok {
			return verdict{}, false
		}
	}

	final, ok := p.Send(node2shellinfra.ContentEncoding, g.Encoding(), g.Bodies.Empty)
	switch {
	case !ok:
		v.stopped = true
	case !node2shellinfra.Same(final, g.Empty):
		// A different page, from a worker that restarted or a pool member that
		// never decoded: the learned classes no longer describe this path, so
		// the probe's match cannot be trusted.
		return verdict{}, false
	}
	return v, true
}

// sendStream delivers one multi-MiB body and reports whether it landed in the
// expected class. A refusal sent off the advertised Content-Length never
// reached the decoder, so it is a failure rather than a class mismatch.
func sendStream(p *node2shellinfra.Prober, g node2shellinfra.Gate, body []byte, want node2shellinfra.Exchange) (node2shellinfra.Exchange, bool) {
	got, ok := p.SendStream(g.Encoding(), body)
	if !ok || refusedBeforeDecode[got.Sig.StatusCode] || !node2shellinfra.Same(got, want) {
		return node2shellinfra.Exchange{}, false
	}
	return got, true
}

func buildResult(v verdict, g node2shellinfra.Gate, scanCtx *modkit.ScanContext, ctx *httpmsg.HttpRequestResponse, target, lane string) *output.ResultEvent {
	decoder := node2shellinfra.LikelyDecoder(scanCtx, modkit.RegistryHostKey(ctx), v.probe.Header)
	extracted := []string{
		"Lane: " + lane,
		"Likely decoder: " + decoder,
		"Decoded encoding: Content-Encoding: " + g.Encoding(),
		fmt.Sprintf("Plain {} -> HTTP %d; malformed { -> HTTP %d; refused stream -> HTTP %d", g.Empty.Sig.StatusCode, g.Malformed.Sig.StatusCode, g.Failed.Sig.StatusCode),
		fmt.Sprintf("Size-matched twin (%d bytes, malformed for every decoder) -> HTTP %d (answered like a refused stream)", node2shellinfra.TwinBytes, v.twin.Sig.StatusCode),
		fmt.Sprintf("%s probe (%d bytes) -> HTTP %d (answered like plain {})", node2shellinfra.CVE, node2shellinfra.ProbeBytes, v.probe.Sig.StatusCode),
		"The two streams differ by one 11-byte repetition, so the divergence follows the decode, not the body size",
		"An affected decoder emits 66 bytes of valid JSON from the probe; a decoder with the fix refuses it",
		fmt.Sprintf("The probe reached the {} class over %d rounds, with all three classes re-proven in between", probeRounds),
		"Endpoint is not volatile: repeated identical requests return one page",
	}
	stability := "the route answered the tiny valid control as before"
	if v.stopped {
		stability = "the route stopped answering after the probe — the host may have been affected by it"
	}
	extracted = append(extracted, "Stability control: "+stability)
	extracted = append(extracted,
		"Decoder version not observable remotely: confirm against the fixed releases ("+node2shellinfra.FixedReleases+")")

	return &output.ResultEvent{
		ModuleID:      ModuleID,
		RecordKind:    output.RecordKindCandidate,
		EvidenceGrade: output.EvidenceGradeDifferential,
		Host:          ctx.Service().Host(),
		URL:           target,
		Matched:       target,
		Request:       v.probe.Request,
		Response:      v.probe.Response,

		ExtractedResults: extracted,
		AdditionalEvidence: []string{
			"Size-matched malformed twin request:\n" + v.twin.Request + "\n\nTwin response:\n" + v.twin.Response,
		},
		Info: output.Info{
			Name: "Potential unpatched Brotli request decoder (node2shell, " + node2shellinfra.CVE + ")",
			Description: fmt.Sprintf(
				"The %s at %s decoded a Brotli stream that only a decoder without the %s fix accepts, and refused the size-matched malformed twin. That points at an unpatched decoder; the build is not observable remotely, so the verdict is a lead.",
				lane, target, node2shellinfra.CVE),
			Severity:   ModuleSeverity,
			Confidence: ModuleConfidence,
			Tags:       []string{"brotli", "cve-2026-111497", "node2shell", "rce"},
			Reference:  node2shellinfra.References,
		},
		Metadata: map[string]any{
			"lane":        lane,
			"encoding":    g.Encoding(),
			"decoder":     decoder,
			"probe_bytes": node2shellinfra.ProbeBytes,
			"twin_bytes":  node2shellinfra.TwinBytes,
			"stable":      !v.stopped,
		},
	}
}
