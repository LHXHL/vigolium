package internal_header_probe

import (
	"fmt"
	"sort"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/oast/oastclass"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

const (
	// selfRounds is how many times the no-header baseline is fetched: the first is
	// the reference, the rest measure the endpoint's natural run-to-run variance.
	selfRounds = 3
	// minSelfStability is the lowest baseline self-similarity at which the endpoint
	// is stable enough to draw conclusions; below it the page varies too much on its
	// own and is skipped to avoid false positives.
	minSelfStability = 0.70
	// noisyMinHeaders / noisyLiveFraction trip the noisy-page breaker: a page that
	// reacts to more than this fraction of its (>= this many) advertised headers is
	// varying on its own rather than exposing a real per-header protocol.
	noisyMinHeaders   = 5
	noisyLiveFraction = 0.50
	// maxFindingsPerHost is the per-host finding budget; once exceeded the host
	// circuit breaker trips and the module stops probing that host for the scan.
	maxFindingsPerHost = 3
	// maxEndpointsPerHost bounds total probed endpoints per host so an inert host
	// with a huge URL surface cannot run up unbounded request volume.
	maxEndpointsPerHost = 25
)

// Module implements the internal-header-probe active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Internal Header Probe module.
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
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("internal_header_probe"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// IncludesBaseCanProcess returns false: this module uses a custom CanProcess that
// gates purely on the advertised-header response, not the base URL/media filters.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess runs only when the response advertises request/response headers via
// the CORS Allow-/Expose-Headers headers — the signal that the host speaks a
// custom header protocol worth probing.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil || ctx.Response() == nil {
		return false
	}
	resp := ctx.Response()
	return resp.Header("Access-Control-Allow-Headers") != "" ||
		resp.Header("Access-Control-Expose-Headers") != ""
}

// ScanPerRequest discovers the advertised custom headers, plants OAST callbacks,
// and reports headers whose response body reproducibly changes with the supplied
// value (beyond the endpoint's natural variance).
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	host := service.Host()

	ds := m.ds.Get(scanCtx.DedupMgr())
	if ds != nil && ds.Contains(disabledKey(host)) {
		return nil, nil // host circuit breaker already tripped this scan
	}

	resp := ctx.Response()
	candidates := selectCandidates(
		resp.Header("Access-Control-Allow-Headers"),
		resp.Header("Access-Control-Expose-Headers"),
	)
	if len(candidates) == 0 {
		return nil, nil
	}

	if ds != nil {
		keyNames := append([]string(nil), candidates...)
		sort.Strings(keyNames)
		if ds.IsSeen(epDedupKey(host, ctx.Request().Method(), urlx.Path, keyNames)) {
			return nil, nil // this endpoint + header-set already probed
		}
		if _, ok := ds.IncrementAndCheck(epBudgetKey(host), maxEndpointsPerHost); !ok {
			return nil, nil // per-host endpoint budget exhausted
		}
	}

	baselineRaw := ctx.Request().Raw()

	// OAST arm — independent of the body-diff arm: a blind SSRF may fire a callback
	// without changing the in-band response, so spray every candidate regardless of
	// stability. Findings (if any) arrive asynchronously via the OAST service.
	m.plantOAST(ctx, httpClient, scanCtx, urlx.String(), baselineRaw, service, candidates)

	// Establish the endpoint's natural variance (the noise floor).
	baseSig, baseStatus, selfRatio, ok := m.measureBaseline(httpClient, service, baselineRaw)
	if !ok || selfRatio < minSelfStability {
		return nil, nil // unreachable, WAF-blocked, or too unstable to judge
	}

	// Phase 1 — cheap screen: one canary probe per header. A header is "live" when
	// even a random value shifts the body beyond the noise floor (value stripped, so
	// a plain reflection of the canary is not mistaken for a behavior change).
	canary := modkit.FreshCanary()
	var live []string
	for _, name := range candidates {
		pr, ok := m.probe(httpClient, service, baselineRaw, name, canary)
		if !ok || pr.blocked {
			continue
		}
		if _, _, diverged := evalProbe(baseSig, selfRatio, pr, canary); diverged {
			live = append(live, name)
		}
	}
	if len(live) == 0 {
		return nil, nil
	}

	// Noisy-page breaker: reacting to nearly every header means the page varies on
	// its own — suppress and stop probing the host.
	if len(candidates) >= noisyMinHeaders &&
		float64(len(live))/float64(len(candidates)) > noisyLiveFraction {
		if ds != nil {
			ds.IsSeen(disabledKey(host))
		}
		return nil, nil
	}

	// Phase 2 — full value battery on live headers, requiring reproducibility. The
	// battery is built once and shared across headers (the UUID need only be unique
	// per endpoint, not per header).
	vals := battery()
	var results []*output.ResultEvent
	for _, name := range live {
		diverging := m.runBattery(httpClient, service, baselineRaw, baseSig, selfRatio, name, vals)
		if len(diverging) == 0 {
			continue // canary screen was a fluke; no value reproducibly diverged
		}
		if ds != nil {
			if _, ok := ds.IncrementAndCheck(findingBudgetKey(host), maxFindingsPerHost); !ok {
				ds.IsSeen(disabledKey(host)) // budget exhausted → stop this host
				break
			}
		}
		results = append(results, m.buildFinding(urlx.String(), name, baseStatus, baseSig.BodyLength, diverging))
	}
	return results, nil
}

// probeResp is a single fetched response, reduced to what the comparison needs.
type probeResp struct {
	status  int
	body    string
	full    string
	blocked bool
}

// fetch re-issues a raw request and returns its reduced response. NoRedirects so a
// header-induced redirect is observed directly; NoClustering so back-to-back
// replays actually re-hit the origin instead of returning a cached body (which
// would collapse the measured variance to zero and defeat the differential).
func (m *Module) fetch(httpClient *http.Requester, service *httpmsg.Service, raw []byte) (probeResp, bool) {
	// raw is internally built (well-formed), so wrap directly instead of
	// re-parsing on this hot path.
	req := httpmsg.NewRequestResponseRaw(raw, service)
	resp, _, err := httpClient.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return probeResp{}, false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return probeResp{}, false
	}
	// Use the WAF/CDN/challenge validator (vendor detection, challenge markers,
	// rate-limit) rather than infra.IsBlockedResponse: the latter also blocks on a
	// bare 401/403 status, which would drop the 401 we deliberately keep (and a
	// genuine auth-bypass-via-header signal where a header turns a 401 into a 200).
	// Status policy is owned by passesStatusGate instead.
	return probeResp{
		status:  resp.Response().StatusCode,
		body:    resp.Body().String(),
		full:    resp.FullResponseString(),
		blocked: infra.GetBlockDetectionValidator().Validate(resp) != nil,
	}, true
}

// probe sets header name=value on the baseline request and fetches the response.
func (m *Module) probe(httpClient *http.Requester, service *httpmsg.Service, baselineRaw []byte, name, value string) (probeResp, bool) {
	raw, err := httpmsg.AddOrReplaceHeader(baselineRaw, name, value)
	if err != nil {
		return probeResp{}, false
	}
	return m.fetch(httpClient, service, raw)
}

// measureBaseline fetches the no-header request selfRounds times and returns the
// reference signature, its status, and the LOWEST same-request similarity observed
// (the natural-variance floor). A status flap across refetches forces the floor to
// 0 (fully non-deterministic). ok is false if any fetch fails or is blocked.
//
// This intentionally does not reuse modkit.ConfirmCrossIDDifferential even though
// the shape is similar (changed-input vs baseline, gated on the baseline's own
// variance): that helper re-measures the baseline on every call, whereas here the
// floor is measured ONCE and reused across every candidate header and probe value
// (many comparisons per endpoint), and compareToBaseline strips the injected value
// from the signature so a reflection of the probe value is never read as a change.
func (m *Module) measureBaseline(httpClient *http.Requester, service *httpmsg.Service, baselineRaw []byte) (modkit.ResponseSignature, int, float64, bool) {
	first, ok := m.fetch(httpClient, service, baselineRaw)
	if !ok || first.blocked || len(first.body) == 0 {
		// A blank baseline body makes the size differential meaningless, so bail.
		return modkit.ResponseSignature{}, 0, 0, false
	}
	baseSig := modkit.NewResponseSignature(first.status, first.body, "")
	selfRatio := 1.0
	for i := 1; i < selfRounds; i++ {
		s, ok := m.fetch(httpClient, service, baselineRaw)
		if !ok || s.blocked {
			return modkit.ResponseSignature{}, 0, 0, false
		}
		if s.status != first.status {
			selfRatio = 0
			continue
		}
		if r := modkit.QuickRatio(baseSig, modkit.NewResponseSignature(s.status, s.body, "")); r < selfRatio {
			selfRatio = r
		}
	}
	return baseSig, first.status, selfRatio, true
}

// valueVerdict records a probe value that reproducibly shifted the response.
type valueVerdict struct {
	label   string
	value   string
	ratio   float64
	status  int
	bodyLen int
	reqRaw  string
	respRaw string
}

// runBattery tests every battery value against the live header and returns the
// values that, in BOTH of two independent rounds (reproducible — not per-request
// dynamic noise), token-diverge from the baseline beyond the noise floor AND drive
// the body to a substantially larger size than the no-header baseline.
func (m *Module) runBattery(httpClient *http.Requester, service *httpmsg.Service, baselineRaw []byte, baseSig modkit.ResponseSignature, selfRatio float64, name string, vals []probeValue) []valueVerdict {
	var out []valueVerdict
	for _, pv := range vals {
		raw, err := httpmsg.AddOrReplaceHeader(baselineRaw, name, pv.value)
		if err != nil {
			continue
		}
		first, ok := m.fetch(httpClient, service, raw)
		if !ok || first.blocked {
			continue
		}
		sig, ratio, diverged := evalProbe(baseSig, selfRatio, first, pv.value)
		if !diverged || !substantiallyLarger(baseSig.BodyLength, sig.BodyLength) {
			continue
		}
		second, ok := m.fetch(httpClient, service, raw)
		if !ok || second.blocked {
			continue
		}
		sig2, _, d2 := evalProbe(baseSig, selfRatio, second, pv.value)
		if !d2 || !substantiallyLarger(baseSig.BodyLength, sig2.BodyLength) {
			continue // not reproducible (token + size) → drop
		}
		out = append(out, valueVerdict{
			label:   pv.label,
			value:   pv.value,
			ratio:   ratio,
			status:  first.status,
			bodyLen: sig.BodyLength,
			reqRaw:  string(raw),
			respRaw: first.full,
		})
	}
	return out
}

// passesStatusGate reports whether a probe response status is one we act on. 2xx,
// 5xx, and 401 are kept; 3xx redirects and all other 4xx (403/404/…) are ignored —
// a header that merely drives a redirect or an error/forbidden page is not the
// "backend processed my value" signal this module reports.
func passesStatusGate(status int) bool {
	if status >= 300 && status < 400 {
		return false
	}
	if status >= 400 && status < 500 && status != 401 {
		return false
	}
	return true
}

// evalProbe gates a probe response and returns its signature, its body similarity
// to the baseline, and whether it token-diverges beyond the noise floor. It drops
// responses we will not act on: a non-reportable status (passesStatusGate) or a
// blank body on either side (a size comparison against an empty body is
// meaningless). The injected value is stripped from the signature so a reflection
// of it is never read as a change.
func evalProbe(baseSig modkit.ResponseSignature, selfRatio float64, pr probeResp, stripValue string) (modkit.ResponseSignature, float64, bool) {
	if !passesStatusGate(pr.status) || baseSig.BodyLength == 0 || len(pr.body) == 0 {
		return modkit.ResponseSignature{}, 0, false
	}
	sig := modkit.NewResponseSignature(pr.status, pr.body, stripValue)
	ratio := modkit.QuickRatio(baseSig, sig)
	return sig, ratio, selfRatio-ratio >= modkit.RatioDiffTolerance
}

// substantiallyLarger reports whether the probe body is a lot bigger than the
// no-header baseline — greater by both an absolute (> SubstantialBodyDeltaBytes)
// and a relative (>= SubstantialBodyDeltaRatio) margin. A header is only reported
// when its value drives the response to a substantially larger body, so a
// same-size content swap or a marginal jitter never qualifies.
func substantiallyLarger(baseLen, probeLen int) bool {
	diff := probeLen - baseLen
	if diff <= modkit.SubstantialBodyDeltaBytes {
		return false
	}
	return float64(diff)/float64(probeLen) >= modkit.SubstantialBodyDeltaRatio
}

// plantOAST sprays an out-of-band callback URL into every candidate header. Best
// effort and fire-and-forget: the OAST service emits any finding asynchronously.
func (m *Module) plantOAST(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
	target string,
	baselineRaw []byte,
	service *httpmsg.Service,
	candidates []string,
) {
	oast := scanCtx.OASTProv()
	if oast == nil || !oast.Enabled() {
		return
	}
	reqHash := ctx.Request().ID()
	for _, name := range candidates {
		ou := modkit.OASTURLFor(oast, oastclass.HeaderHarvest, target, name, "internal-header", ModuleID, reqHash)
		if ou == "" {
			continue
		}
		raw, err := httpmsg.AddOrReplaceHeader(baselineRaw, name, "http://"+ou)
		if err != nil {
			continue
		}
		// raw is internally built (well-formed), so wrap directly instead of
		// re-parsing on this hot path.
		req := httpmsg.NewRequestResponseRaw(raw, service)
		resp, _, err := httpClient.Execute(req, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return
			}
			continue
		}
		resp.Close()
	}
}

// buildFinding assembles one Suspect/Tentative finding for a header whose value
// reproducibly drives a response-body change.
func (m *Module) buildFinding(target, name string, baseStatus, baseLen int, verdicts []valueVerdict) *output.ResultEvent {
	extracted := []string{
		fmt.Sprintf("Header: %s", name),
		fmt.Sprintf("Baseline status: %d, body: %d bytes", baseStatus, baseLen),
	}
	var evidence []string
	for _, v := range verdicts {
		shown := v.value
		if shown == "" {
			shown = "(empty)"
		}
		statusNote := ""
		if v.status != baseStatus {
			statusNote = fmt.Sprintf(", status %d→%d", baseStatus, v.status)
		}
		sizeNote := fmt.Sprintf(", body %d→%d bytes", baseLen, v.bodyLen)
		extracted = append(extracted, fmt.Sprintf("%s=%q → similarity %.2f%s%s", name, shown, v.ratio, statusNote, sizeNote))
		evidence = append(evidence, output.BuildEvidence(
			fmt.Sprintf("%s: %s=%q (similarity %.2f%s%s)", v.label, name, shown, v.ratio, statusNote, sizeNote),
			v.reqRaw, v.respRaw))
	}
	return &output.ResultEvent{
		URL:                target,
		Matched:            target,
		Request:            verdicts[0].reqRaw,
		Response:           verdicts[0].respRaw,
		ExtractedResults:   extracted,
		AdditionalEvidence: evidence,
		Info: output.Info{
			Name: fmt.Sprintf("Internal Header Influences Response: %s", name),
			Description: fmt.Sprintf(
				"The server advertises the custom request header %q via Access-Control-Allow-Headers / "+
					"Access-Control-Expose-Headers, and supplying a value for it reproducibly grows the response "+
					"to a substantially larger body than the no-header baseline (the baseline's own variance stayed "+
					"below the divergence tolerance, the size increase exceeded both an absolute and a relative "+
					"margin, the response was an actionable status — 2xx/401/5xx, not a 3xx/4xx redirect or error — "+
					"and the injected value was stripped before comparison to exclude mere reflection). This "+
					"indicates the backend processes a client-supplied value for an internal / gateway header. "+
					"Review whether the value can influence identity, authorization, routing, or information "+
					"disclosure — this is an exploratory signal, not a confirmed vulnerability.", name),
			Severity:   ModuleSeverity,
			Confidence: ModuleConfidence,
			Tags:       ModuleTags,
			Reference: []string{
				"https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface",
				"https://portswigger.net/web-security/cors",
			},
		},
		Metadata: map[string]any{
			"header":           name,
			"baseline_status":  baseStatus,
			"diverging_values": len(verdicts),
		},
	}
}

// --- dedup / circuit-breaker keys (all share one DiskSet via distinct prefixes) ---

func epDedupKey(host, method, path string, sortedNames []string) string {
	return "ep:" + utils.Sha1(strings.Join([]string{host, method, path, strings.Join(sortedNames, ",")}, "\x00"))
}

func disabledKey(host string) string      { return "off:" + host }
func epBudgetKey(host string) string      { return "epb:" + host }
func findingBudgetKey(host string) string { return "fc:" + host }
