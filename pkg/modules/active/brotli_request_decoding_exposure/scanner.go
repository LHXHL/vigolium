package brotli_request_decoding_exposure

import (
	"fmt"
	nethttp "net/http"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

const (
	// probePath is a route no app defines: an app-wide parser (NestJS, a global
	// app.use(express.json())) or a decoding proxy runs before routing, so the
	// probe is decoded without reaching any handler.
	probePath = "/vigolium-brotli-decoder-check"
	// unknownEncoding is the control encoding. A server that drops or ignores the
	// body of any encoded request answers it like the decoded Brotli probe.
	unknownEncoding = "x-vigolium"
	// decoyHeader is a header no server reads. It carries a random value to
	// show odd headers alone do not move the answer, and the encoding name to
	// show decoding is tied to Content-Encoding rather than to any header.
	decoyHeader = "X-Vigolium-Encoding"
	// stackedEncoding is tried when plain br is refused: a guard that checks only
	// the first token lets it through to a decoder that handles both.
	stackedEncoding = "gzip, br"
	// maxRoutesPerOrigin caps how many recorded routes are probed per origin when
	// the host probe shows nothing (the parser may be mounted per route).
	maxRoutesPerOrigin = 3
	// confirmRounds is how many times the encoded pair must be answered like
	// the plain pair before the origin is reported.
	confirmRounds = 2
)

// encodedBodies is one Content-Encoding with emptyBody and malformedBody
// encoded under it.
type encodedBodies struct {
	encoding         string
	empty, malformed []byte
}

var (
	// emptyBody is valid JSON a handler can only refuse or accept as empty;
	// malformedBody is what every JSON parser refuses. A route that answers
	// both the same does not read its body and carries no signal.
	emptyBody     = []byte("{}")
	malformedBody = []byte("{")
	// The encoded bodies are emptyBody and malformedBody encoded as br and as
	// "gzip, br" (gzip applied first), precomputed so no encoder runs at startup
	// (TestEncodedProbesRoundTrip decodes them back). Tiny well-formed streams:
	// ordinary decoder use, nowhere near the CVE-2026-111497 trigger.
	encodings = []encodedBodies{
		{
			encoding:  "br",
			empty:     []byte{0x8b, 0x00, 0x80, 0x7b, 0x7d, 0x03},
			malformed: []byte{0x0b, 0x00, 0x80, 0x7b, 0x03},
		},
		{
			encoding: stackedEncoding,
			empty: []byte{
				0x0b, 0x0d, 0x80, 0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x02, 0x00,
				0xfd, 0xff, 0x7b, 0x7d, 0x03, 0x00, 0x43, 0xbf, 0xa6, 0xa3, 0x02, 0x00, 0x00, 0x00, 0x03,
			},
			malformed: []byte{
				0x8b, 0x0c, 0x80, 0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x01, 0x00,
				0xfe, 0xff, 0x7b, 0x03, 0x00, 0x39, 0x47, 0xd5, 0x15, 0x01, 0x00, 0x00, 0x00, 0x03,
			},
		},
	}
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
	return m.scan(ctx, httpClient, scanCtx, "POST", probePath, "application/json", "app-wide parser or proxy")
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
	if !carriesJSONBody(method, contentType) {
		return nil, nil
	}
	if ds := m.ds.Get(scanCtx.DedupMgr()); ds != nil {
		origin := originOf(ctx)
		if ds.Contains("found|"+origin) || ds.Contains("exhausted|"+origin) ||
			ds.IsSeen("route|"+origin+"|"+method+" "+ctx.Request().Path()) {
			return nil, nil
		}
		if _, ok := ds.IncrementAndCheck("routes|"+origin, maxRoutesPerOrigin); !ok {
			ds.IsSeen("exhausted|" + origin)
			return nil, nil
		}
	}
	return m.scan(ctx, httpClient, scanCtx, method, ctx.Request().Path(), contentType, "route body parser")
}

// scan runs the differential on one method+path and records a hit so the
// origin is reported once.
func (m *Module) scan(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, scanCtx *modkit.ScanContext, method, path, contentType, lane string) ([]*output.ResultEvent, error) {
	origin := originOf(ctx)
	ds := m.ds.Get(scanCtx.DedupMgr())
	if ds != nil && ds.Contains("found|"+origin) {
		return nil, nil
	}
	p, ok := newProber(ctx, httpClient, method, path, contentType)
	if !ok {
		return nil, nil
	}
	r := check(p, scanCtx, ctx, origin+path, lane)
	if r == nil {
		return nil, nil
	}
	if ds != nil {
		ds.IsSeen("found|" + origin)
	}
	return []*output.ResultEvent{r}, nil
}

func originOf(ctx *httpmsg.HttpRequestResponse) string {
	u, err := ctx.URL()
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// carriesJSONBody reports whether a recorded request is one the differential
// can probe: a POST or PATCH with a JSON body. PUT is skipped because PUT {}
// can replace a resource; the oracle needs malformed JSON, so form and text
// bodies are not probed.
func carriesJSONBody(method, contentType string) bool {
	return (method == "POST" || method == "PATCH") &&
		modkit.ClassifyContentType(contentType) == modkit.ContentClassJSON
}

// check runs the decode differential. The answer must follow the decoded
// content, not the header:
//   - the path reads its body: plain {} and plain { are answered differently,
//     and plain {} is not a 5xx or 429 (an erroring or throttled baseline
//     matches anything);
//   - encoded {} is answered like plain {} and encoded { like plain {, for
//     confirmRounds rounds. A server that reacts to the header alone (a WAF
//     block, a 4xx/5xx with odd headers, a dropped body) answers both encoded
//     bodies alike, and a flaky one breaks on the repeat;
//   - the same bytes under an unknown encoding are not answered like plain {};
//   - header decoys: plain {} with a random X-Vigolium-Encoding is answered
//     like plain {}, and the encoded bytes with X-Vigolium-Encoding naming the
//     encoding (no Content-Encoding) are not.
//
// A server that ignores Content-Encoding sees the Brotli bytes as malformed
// JSON and stops at the first encoded probe.
func check(p prober, scanCtx *modkit.ScanContext, ctx *httpmsg.HttpRequestResponse, target, lane string) *output.ResultEvent {
	empty, ok := p.send("", emptyBody)
	if !ok || unreliable(empty) {
		return nil
	}
	malformed, ok := p.send("", malformedBody)
	if !ok || same(empty, malformed) {
		return nil
	}

	var enc encodedBodies
	var decoded exchange
	for _, e := range encodings {
		d, ok := p.send(e.encoding, e.empty)
		if !ok {
			return nil
		}
		if same(d, empty) {
			enc, decoded = e, d
			break
		}
		// Brotli bytes parsed as malformed JSON: nothing decodes br here, so a
		// stacked encoding will not decode either.
		if same(d, malformed) {
			return nil
		}
	}
	if enc.encoding == "" {
		return nil
	}
	var decodedMalformed exchange
	for round := 0; round < confirmRounds; round++ {
		if round > 0 {
			if d, ok := p.send(enc.encoding, enc.empty); !ok || !same(d, empty) {
				return nil
			}
		}
		if decodedMalformed, ok = p.send(enc.encoding, enc.malformed); !ok || !same(decodedMalformed, malformed) {
			return nil
		}
	}
	unknown, ok := p.send(unknownEncoding, enc.empty)
	if !ok || same(unknown, empty) {
		return nil
	}
	// Header decoys. An odd header alone must not move the answer, or the
	// unknown-encoding control differing proves nothing about Content-Encoding.
	// And the encoded bytes under a header that merely names br must not be
	// decoded: the decoded answer belongs to Content-Encoding itself.
	noise, ok := p.sendHeader(decoyHeader, modkit.RandomAlnum(12), emptyBody)
	if !ok || !same(noise, empty) {
		return nil
	}
	misplaced, ok := p.sendHeader(decoyHeader, enc.encoding, enc.empty)
	if !ok || same(misplaced, empty) {
		return nil
	}
	encoding := enc.encoding

	decoder := likelyDecoder(scanCtx, modkit.RegistryHostKey(ctx), decoded.header)
	return &output.ResultEvent{
		ModuleID:      ModuleID,
		RecordKind:    output.RecordKindCandidate,
		EvidenceGrade: output.EvidenceGradeDifferential,
		Host:          ctx.Service().Host(),
		URL:           target,
		Matched:       target,
		Request:       decoded.request,
		Response:      decoded.response,
		ExtractedResults: []string{
			"Lane: " + lane,
			"Likely decoder: " + decoder,
			fmt.Sprintf("Plain {} -> HTTP %d; malformed { -> HTTP %d", empty.sig.StatusCode, malformed.sig.StatusCode),
			fmt.Sprintf("Content-Encoding: %s {} -> HTTP %d (answered like plain {})", encoding, decoded.sig.StatusCode),
			fmt.Sprintf("Content-Encoding: %s { -> HTTP %d (answered like plain {)", encoding, decodedMalformed.sig.StatusCode),
			fmt.Sprintf("Encoded pair held over %d rounds", confirmRounds),
			fmt.Sprintf("Content-Encoding: %s, same bytes -> HTTP %d (not decoded)", unknownEncoding, unknown.sig.StatusCode),
			fmt.Sprintf("%s: <random>, plain {} -> HTTP %d (odd header ignored)", decoyHeader, noise.sig.StatusCode),
			fmt.Sprintf("%s: %s, same bytes, no Content-Encoding -> HTTP %d (not decoded)", decoyHeader, encoding, misplaced.sig.StatusCode),
			"Decoder version not observable: check it against the CVE-2026-111497 fixed releases",
		},
		AdditionalEvidence: []string{
			"Unknown-encoding control request:\n" + unknown.request + "\n\nControl response:\n" + unknown.response,
		},
		Info: output.Info{
			Name:        "Potential Brotli request-body decoding (CVE-2026-111497 exposure)",
			Description: fmt.Sprintf("The %s at %s decodes Content-Encoding: %s request bodies. If that decoder is an affected Brotli build, CVE-2026-111497 is reachable.", lane, target, encoding),
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        []string{"brotli", "cve-2026-111497", "node2shell"},
			Reference: []string{
				"https://patchtheplanet.org/brotli",
				"https://nodejs.org/en/blog/vulnerability/october-2026-security-releases",
				"https://istio.io/latest/news/security/istio-security-2026-007/",
				"https://github.com/google/brotli/releases/tag/v1.2.1",
			},
		},
		Metadata: map[string]any{
			"lane":     lane,
			"encoding": encoding,
			"decoder":  decoder,
		},
	}
}

// likelyDecoder names the component that probably decoded the body. A proxy in
// the path is named first: it decodes before the app, and a Python or Go app
// behind it is exposed only through it. Envoy and Bun have no fingerprint tag,
// so their headers are read here; app stacks come from the tech registry. The
// label is a hint for the reader, never a gate.
func likelyDecoder(scanCtx *modkit.ScanContext, host string, header nethttp.Header) string {
	server := strings.ToLower(header.Get("Server"))
	switch {
	case strings.Contains(server, "envoy") || header.Get("X-Envoy-Upstream-Service-Time") != "":
		return "Envoy/Istio proxy in path (the proxy's decompressor, or the app behind it)"
	case strings.Contains(server, "bun"):
		return "Bun"
	case scanCtx.HasAnyTech(host, []string{"express", "nestjs", "nextjs", "nodejs"}):
		return "Node.js app (body parser)"
	case scanCtx.HasAnyTech(host, []string{"python", "django", "flask", "fastapi"}):
		return "Python app (custom decoding middleware, or an unseen proxy in front)"
	}
	return "unidentified"
}

// prober replays one method+path with varying body and Content-Encoding. The
// request is rebuilt once; each probe only swaps those two.
type prober struct {
	ctx    *httpmsg.HttpRequestResponse
	client *http.Requester
	base   []byte
}

func newProber(ctx *httpmsg.HttpRequestResponse, client *http.Requester, method, path, contentType string) (prober, bool) {
	raw, err := httpmsg.SetMethod(ctx.Request().Raw(), method)
	if err == nil {
		raw, err = httpmsg.SetPath(raw, path)
	}
	if err == nil {
		raw, err = httpmsg.RemoveHeader(raw, "Transfer-Encoding")
	}
	if err == nil {
		raw, err = httpmsg.AddOrReplaceHeader(raw, "Content-Type", contentType)
	}
	if err == nil {
		raw, err = httpmsg.RemoveHeader(raw, "Content-Encoding")
	}
	return prober{ctx: ctx, client: client, base: raw}, err == nil
}

type exchange struct {
	sig      modkit.ResponseSignature
	header   nethttp.Header
	request  string
	response string
}

// same reports whether two answers are the same page: equal status and a
// similar body.
func same(a, b exchange) bool { return modkit.RatioSimilar(a.sig, b.sig) }

// unreliable reports a baseline that cannot anchor the differential: a server
// error or a throttle answers every probe alike.
func unreliable(e exchange) bool {
	return e.sig.StatusCode >= 500 || e.sig.StatusCode == nethttp.StatusTooManyRequests
}

// send fires the base request with the given body and Content-Encoding (none
// when empty).
func (p prober) send(encoding string, body []byte) (exchange, bool) {
	return p.sendHeader("Content-Encoding", encoding, body)
}

// sendHeader fires the base request with the given body and one extra header
// (none when value is empty). Redirects are not followed and the response
// cache is bypassed (probes differ only in a header or a byte).
func (p prober) sendHeader(name, value string, body []byte) (exchange, bool) {
	raw := p.base
	var err error
	if value != "" {
		if raw, err = httpmsg.AddOrReplaceHeader(raw, name, value); err != nil {
			return exchange{}, false
		}
	}
	if raw, err = httpmsg.SetBody(raw, body); err != nil {
		return exchange{}, false
	}
	req := httpmsg.NewRequestResponseRaw(raw, p.ctx.Service())
	resp, _, err := p.client.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return exchange{}, false
	}
	defer resp.Close()
	hr := resp.Response()
	if hr == nil {
		return exchange{}, false
	}
	return exchange{
		sig:      modkit.NewResponseSignature(hr.StatusCode, resp.BodyString(), ""),
		header:   hr.Header,
		request:  string(raw),
		response: modkit.Truncate(resp.FullResponseString(), 2048),
	}, true
}
