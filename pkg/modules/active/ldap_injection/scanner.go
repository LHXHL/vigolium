package ldap_injection

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// Boolean-based differential thresholds. A wildcard response is only flagged
// when it diverges from the comparison signature by BOTH an absolute and a
// relative margin — status-only flips and small content drift don't count.
const (
	booleanMinAbsoluteDelta = 100
	booleanMinRelativeDelta = 0.30
)

// controlPayload is the "no-match" probe paired with the wildcard. It looks
// like ordinary parameter data (no LDAP metacharacters, no WAF triggers) and
// is overwhelmingly unlikely to match any real LDAP attribute, giving a stable
// reference for what the endpoint returns when the value just doesn't match.
const controlPayload = "vigolium_ldap_nomatch_zZ9qX7cB"

// ldapErrorPatterns are lowercased substrings that indicate a genuine LDAP-layer
// error in a response body. Every entry must be specific to LDAP: bare generic
// tokens ("ldap", "search filter", "invalid attribute", "filter error") were
// removed because they are ordinary English/UI phrasing — "Login with LDAP", a
// "clear search filter" button, a form "invalid attribute" validation message —
// that a broadly-named param (user/name/email/search/query) can surface on a
// benign page, producing a Medium "LDAP Injection: error-based" false positive
// (the same generic-token-on-a-benign-body class as the Oracle.*?Driver FP). The
// remaining entries name a driver class, a standard LDAP error envelope, or an
// LDAP-specific filter/DN error phrase, none of which occur in ordinary content.
var ldapErrorPatterns = []string{
	"javax.naming",
	"com.sun.jndi.ldap",
	"ldapexception",
	"ldap: error code", // OpenLDAP / JNDI standard form, e.g. "LDAP: error code 49"
	"ldap_search",
	"ldap_bind",
	"ldap_connect",
	"invalid dn",
	"bad search filter",
	"unrecognized search filter",
	"invalid attribute syntax",
	"malformed filter",
	"error in filter",
	"expected filter",
}

// ldapParamNames are parameter name substrings that suggest LDAP involvement.
var ldapParamNames = []string{
	"username", "user", "login", "uid", "cn", "dn", "filter",
	"search", "query", "name", "email", "mail", "sn", "givenname",
	"ou", "group", "member", "objectclass", "base", "scope", "ldap",
	"password", "pass", "pwd",
}

// ldapPayloads are LDAP filter injection strings for error-based detection.
var ldapPayloads = []string{
	")(objectClass=*",
	"*)(uid=*))(|(uid=*",
	"*)(|(objectClass=*",
	"*)(objectClass=*))(&(objectClass=",
	"\\00",
	")(cn=*",
}

// negationTruePayload / negationFalsePayload are a boolean-oracle pair that differ
// by exactly one character: the disjunction operator `|` (always-true sub-filter)
// versus the negation operator `!` (its complement, matches nothing). Injected into
// an LDAP filter clause such as (&(uid=X)(userPassword=Y)), the TRUE variant widens
// the result set to every entry while the FALSE variant collapses it to none, so
// the two responses diverge sharply. An ordinary application search treats both as
// the same literal string (one character apart) and returns the same page, which is
// exactly why a substantial TRUE-vs-FALSE divergence is a far more LDAP-specific
// signal than the wildcard differential — a plain text search cannot interpret
// `!( … )` as negation.
const (
	negationTruePayload  = "*)(|(objectClass=*))"
	negationFalsePayload = "*)(!(objectClass=*))"
)

// Module implements the LDAP injection active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new LDAP Injection module.
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
			modkit.ScanScopeInsertionPoint,
			modkit.AllParamTypes,
		),
		rhm: dedup.LazyDefaultRHM("ldap_injection"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// VulnClass enables cross-module (param, class) dedup: once any ldap module
// reports a parameter, the others in the class skip it.
func (m *Module) VulnClass() string { return modkit.VulnClassLDAP }

// ScanPerInsertionPoint tests LDAP injection in parameters with LDAP-related names.
func (m *Module) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// Reject media/JS URLs, OPTIONS/CONNECT, and CDN-edge infra paths (/cdn-cgi/):
	// none route to an LDAP-backed application, and a CDN challenge endpoint returns
	// an opaque per-request body that fools the wildcard differential.
	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return nil, nil
	}

	// Only test parameters whose name suggests LDAP usage
	if !isLDAPRelatedParam(ip.Name()) {
		return nil, nil
	}

	// Dedup by request hash + param via RHM
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramName := ip.Name()
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), paramName, ip.BaseValue(), paramType) {
			return nil, nil
		}
	}

	// Get baseline response body
	var baselineBody string
	var baselineStatus int
	if ctx.Response() != nil {
		baselineBody = ctx.Response().BodyToString()
		baselineStatus = ctx.Response().StatusCode()
	}

	// Skip if baseline already contains LDAP error strings
	if containsLDAPError(baselineBody) {
		return nil, nil
	}

	var results []*output.ResultEvent

	// Error-based detection: inject malformed LDAP filter syntax
	for _, payload := range ldapPayloads {
		fuzzedRaw := ip.BuildRequest([]byte(payload))

		// BuildRequest produces well-formed raw, so wrap directly instead
		// of re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(fuzzedRaw, ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		// A WAF/CDN challenge, auth gate, or rate-limit page is not the app
		// surfacing an LDAP error — skip it so its content can't trip the
		// signature (the SSO/Cloudflare-challenge false-positive class).
		if infra.IsBlockedResponse(resp) {
			resp.Close()
			continue
		}

		body := resp.Body().String()
		if containsLDAPError(body) {
			results = append(results, &output.ResultEvent{
				URL:              urlx.String(),
				Matched:          urlx.String(),
				Request:          string(fuzzedRaw),
				Response:         resp.FullResponseString(),
				FuzzingParameter: ip.Name(),
				ExtractedResults: []string{findLDAPError(body)},
				Info: output.Info{
					Name:        "LDAP Injection: error-based",
					Description: fmt.Sprintf("LDAP error triggered by injecting %q into parameter %q", payload, ip.Name()),
				},
			})
			resp.Close()
			return results, nil
		}
		resp.Close()
	}

	// Boolean-based detection is a body-size differential, so skip it on an unreliable
	// surface — a cache/CDN-fronted response (HIT/MISS swings), a large rendered HTML
	// page (per-request dynamic content), or an opaque high-entropy body (encrypted
	// CDN/challenge blob) all manufacture phantom wildcard-vs-control deltas. The
	// error-based pass above is a token match and is unaffected, so it still runs.
	if modkit.DifferentialSurfaceUnreliable(ctx.Response()) {
		return results, nil
	}

	baselineSig := newResponseSignature(baselineStatus, baselineBody)

	// Negation boolean oracle: an LDAP-specific TRUE/FALSE pair that differs by a
	// single operator character. It is a stronger (more LDAP-specific) signal than
	// the wildcard differential, so it runs first; the wildcard leg below is the
	// fallback for surfaces where the negation form doesn't apply.
	if r := m.detectNegationOracle(ctx, ip, httpClient, urlx.String(), baselineSig); r != nil {
		results = append(results, r)
		return results, nil
	}

	// Boolean-based detection: send a TRUE-like wildcard probe and a
	// "no-match" control probe alongside the baseline. The wildcard is only
	// flagged if its response is *uniquely* different — substantially diverging
	// from BOTH the baseline AND the control. Comparing against a control
	// filters out endpoints that simply reflect any user input (search forms
	// echoing the query, dynamic listings, etc.), where wildcard and control
	// would both differ from baseline by similar amounts but look like each
	// other. Genuine LDAP filter expansion produces a wildcard response that
	// no normal value (control) can reproduce.
	wildcardRaw := ip.BuildRequest([]byte("*"))
	wildcardSig, wildcardFull, ok := m.probeSignature(ctx, httpClient, wildcardRaw)
	if !ok {
		return results, nil
	}

	controlRaw := ip.BuildRequest([]byte(controlPayload))
	controlSig, _, ok := m.probeSignature(ctx, httpClient, controlRaw)
	if !ok {
		return results, nil
	}

	// Suppress when either probe is blocked by a WAF/auth/rate-limit layer but
	// the baseline wasn't — the gateway is reacting to the probe value, not the
	// app interpreting it as an LDAP filter. The block page also explains any
	// body-length delta.
	if !isAccessDenied(baselineStatus) {
		if isAccessDenied(wildcardSig.statusCode) || isAccessDenied(controlSig.statusCode) {
			return results, nil
		}
	}

	// Status discipline: LDAP filter expansion changes the RESULT SET rendered on
	// the same page, not the HTTP status. A wildcard that flips the status
	// (baseline 200 → wildcard 500/302/404, or the reverse) is a status artifact —
	// an error page, redirect, or not-found — not a boolean oracle, and its body
	// naturally differs from a 200 baseline. isAccessDenied only screens
	// 401/403/429/503, so 500/302/404 would otherwise slip through. Require all three
	// responses to share one 2xx status before trusting a body-size differential.
	if !infra.Is2xx(baselineSig.statusCode) || !infra.Is2xx(wildcardSig.statusCode) || !infra.Is2xx(controlSig.statusCode) {
		return results, nil
	}
	if wildcardSig.statusCode != baselineSig.statusCode || wildcardSig.statusCode != controlSig.statusCode {
		return results, nil
	}

	// Require the wildcard response to diverge substantially from BOTH the baseline
	// AND the control. This is a pure comparison over responses already in hand, so
	// it runs BEFORE the (network-bound) determinism/reproduction re-fetches below —
	// the overwhelmingly common non-injectable param (wildcard body ≈ baseline)
	// short-circuits here without paying for those extra round-trips.
	if !hasSubstantialBodyDifference(wildcardSig, baselineSig) {
		return results, nil
	}
	if !hasSubstantialBodyDifference(wildcardSig, controlSig) {
		return results, nil
	}

	// Determinism precondition. The wildcard-vs-baseline/control deltas only mean
	// "LDAP filter expansion" if the endpoint answers the SAME input the SAME way.
	// The params this module targets (user/search/query/name/email) are exactly the
	// ones rendered into search-result pages whose size varies per request (result
	// counts, ads, tokens, timestamps); on those a `*` that merely matches more rows
	// than a specific term — ordinary application search, not LDAP — clears the
	// deltas. Re-fetch the original value twice and require a stable body; a flapping
	// or dynamic page fails closed. NoClustering (in probeSignature) makes each a
	// genuine round-trip so the 500ms request cache can't hide the variance.
	if !m.baseValueDeterministic(ctx, ip, httpClient) {
		return results, nil // original value is non-deterministic — differential is noise
	}

	// Reproduction: re-send the wildcard and require its response to be stable. A
	// one-off anomaly (a transient large page or error render) that happened to clear
	// the deltas on the first probe will not reproduce here.
	if !m.signatureReproduces(ctx, httpClient, wildcardRaw, wildcardSig) {
		return results, nil // wildcard response is not reproducible
	}

	results = append(results, &output.ResultEvent{
		URL:              urlx.String(),
		Matched:          urlx.String(),
		Request:          string(wildcardRaw),
		Response:         wildcardFull,
		FuzzingParameter: ip.Name(),
		ExtractedResults: []string{fmt.Sprintf(
			"baseline_status=%d baseline_len=%d wildcard_status=%d wildcard_len=%d control_status=%d control_len=%d",
			baselineSig.statusCode, baselineSig.bodyLength,
			wildcardSig.statusCode, wildcardSig.bodyLength,
			controlSig.statusCode, controlSig.bodyLength,
		)},
		Info: output.Info{
			Name:        "LDAP Injection: boolean-based",
			Description: fmt.Sprintf("Wildcard injection in parameter %q produced a response that differs substantially from both the baseline and a no-match control, suggesting LDAP filter manipulation", ip.Name()),
			// The wildcard differential is an in-band heuristic (a `*` may widen an
			// ordinary application search just as it widens an LDAP filter), so it is
			// reported Tentative even after the determinism/reproduction gates — below
			// the error-based leg, whose LDAP-specific token match warrants Firm.
			Confidence: severity.Tentative,
		},
	})

	return results, nil
}

// detectNegationOracle runs the LDAP-specific negation boolean oracle. It sends a
// TRUE (disjunction) and a FALSE (negation) filter that differ by a single operator
// character and requires the two responses to diverge substantially — a divergence
// an ordinary text search (which sees a one-character difference) cannot produce.
// It applies the same discipline as the wildcard leg — both probes 2xx and
// same-status, not gated by a WAF/auth page, the base value deterministic, and each
// probe reproducible — before reporting. Returns nil (no finding) on any failed gate.
func (m *Module) detectNegationOracle(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	urlStr string,
	baselineSig responseSignature,
) *output.ResultEvent {
	trueRaw := ip.BuildRequest([]byte(negationTruePayload))
	trueSig, trueFull, ok := m.probeSignature(ctx, httpClient, trueRaw)
	if !ok {
		return nil
	}

	falseRaw := ip.BuildRequest([]byte(negationFalsePayload))
	falseSig, _, ok := m.probeSignature(ctx, httpClient, falseRaw)
	if !ok {
		return nil
	}

	// A WAF/auth/rate-limit page on either probe (when the baseline wasn't blocked)
	// is the gateway reacting to filter metacharacters, not the app expanding a
	// filter — the block body would also manufacture a divergence.
	if !isAccessDenied(baselineSig.statusCode) {
		if isAccessDenied(trueSig.statusCode) || isAccessDenied(falseSig.statusCode) {
			return nil
		}
	}

	// Status discipline: the oracle changes the rendered result set, not the HTTP
	// status. Require all three responses to share one 2xx status before trusting a
	// body-size differential (a status flip is an error/redirect artifact).
	if !infra.Is2xx(baselineSig.statusCode) || !infra.Is2xx(trueSig.statusCode) || !infra.Is2xx(falseSig.statusCode) {
		return nil
	}
	if trueSig.statusCode != falseSig.statusCode || trueSig.statusCode != baselineSig.statusCode {
		return nil
	}

	// Core signal: TRUE (match-all) and FALSE (match-none) must diverge substantially.
	// Cheap comparison over responses already in hand — runs before the network-bound
	// determinism/reproduction re-fetches so a non-injectable param short-circuits.
	if !hasSubstantialBodyDifference(trueSig, falseSig) {
		return nil
	}

	// Determinism precondition: the base value fetched twice must be stable, otherwise
	// the endpoint is dynamic and the TRUE/FALSE delta is noise.
	if !m.baseValueDeterministic(ctx, ip, httpClient) {
		return nil
	}

	// Reproduction: re-send both probes and require each to reproduce, so a one-off
	// render that happened to create the delta is rejected.
	if !m.signatureReproduces(ctx, httpClient, trueRaw, trueSig) ||
		!m.signatureReproduces(ctx, httpClient, falseRaw, falseSig) {
		return nil
	}

	return &output.ResultEvent{
		URL:              urlStr,
		Matched:          urlStr,
		Request:          string(trueRaw),
		Response:         trueFull,
		FuzzingParameter: ip.Name(),
		ExtractedResults: []string{fmt.Sprintf(
			"true_status=%d true_len=%d false_status=%d false_len=%d baseline_status=%d baseline_len=%d",
			trueSig.statusCode, trueSig.bodyLength,
			falseSig.statusCode, falseSig.bodyLength,
			baselineSig.statusCode, baselineSig.bodyLength,
		)},
		Info: output.Info{
			Name: "LDAP Injection: boolean-based (negation oracle)",
			Description: fmt.Sprintf(
				"Parameter %q behaves as an LDAP boolean oracle: an always-true disjunction and its negation "+
					"(differing by a single operator character) produced substantially divergent, reproducible responses. "+
					"A plain text search cannot interpret `!( … )` as negation, so this indicates the value is embedded in an LDAP filter.",
				ip.Name(),
			),
			// Still an in-band differential (no LDAP error string), so reported Tentative,
			// though the negation-operator specificity makes it a stronger lead than the
			// wildcard leg.
			Confidence: severity.Tentative,
		},
	}
}

// baseValueDeterministic re-fetches the insertion point's original value twice and
// reports whether the endpoint answers it the same way both times. A flapping /
// dynamic page (per-request result counts, tokens, timestamps) fails closed so its
// variance is not mistaken for filter expansion. Shared by both boolean legs.
func (m *Module) baseValueDeterministic(ctx *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint, httpClient *http.Requester) bool {
	origRaw := ip.BuildRequest([]byte(ip.BaseValue()))
	det1, _, ok1 := m.probeSignature(ctx, httpClient, origRaw)
	det2, _, ok2 := m.probeSignature(ctx, httpClient, origRaw)
	if !ok1 || !ok2 {
		return false
	}
	return det1.statusCode == det2.statusCode && !hasSubstantialBodyDifference(det1, det2)
}

// signatureReproduces re-sends raw and reports whether the response still matches orig
// (same status, no substantial body difference), so a one-off anomaly that happened to
// clear the deltas on the first probe is rejected. Shared by both boolean legs.
func (m *Module) signatureReproduces(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, raw []byte, orig responseSignature) bool {
	sig2, _, ok := m.probeSignature(ctx, httpClient, raw)
	if !ok {
		return false
	}
	return sig2.statusCode == orig.statusCode && !hasSubstantialBodyDifference(orig, sig2)
}

// responseSignature captures key response attributes for differential comparison.
type responseSignature struct {
	statusCode int
	bodyLength int
	bodyHash   [32]byte
}

func newResponseSignature(statusCode int, body string) responseSignature {
	return responseSignature{
		statusCode: statusCode,
		bodyLength: len(body),
		bodyHash:   sha256.Sum256([]byte(body)),
	}
}

// hasSubstantialBodyDifference reports whether two responses diverge by both an
// absolute (>booleanMinAbsoluteDelta bytes) and a relative
// (>=booleanMinRelativeDelta) margin. Status-code flips alone are not enough —
// the body content has to actually change in a meaningful way, which is what
// LDAP filter manipulation produces (filter expanded → more matched records →
// larger or structurally different page).
func hasSubstantialBodyDifference(a, b responseSignature) bool {
	if a.bodyHash == b.bodyHash {
		return false
	}
	diff := a.bodyLength - b.bodyLength
	if diff < 0 {
		diff = -diff
	}
	if diff <= booleanMinAbsoluteDelta {
		return false
	}
	maxLen := a.bodyLength
	if b.bodyLength > maxLen {
		maxLen = b.bodyLength
	}
	if maxLen == 0 {
		return false
	}
	return float64(diff)/float64(maxLen) >= booleanMinRelativeDelta
}

// probeSignature sends a single fuzzed request and returns its response
// signature along with the full response string. The boolean ok is false when
// the request couldn't be sent or the host became unresponsive — callers
// should abort the boolean-based pass in that case rather than treat the
// missing probe as evidence.
func (m *Module) probeSignature(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	rawReq []byte,
) (responseSignature, string, bool) {
	// rawReq is internally built (well-formed), so wrap directly instead of
	// re-parsing on this hot path.
	req := httpmsg.NewRequestResponseRaw(rawReq, ctx.Service())

	// NoClustering: the boolean leg re-sends IDENTICAL requests to prove the endpoint
	// is deterministic (the original value fetched twice) and that the wildcard
	// response reproduces. The 500ms request-cluster cache keys on raw request bytes,
	// so without this a re-fetch returns the first response's cached copy and the
	// stability checks pass trivially even on a flapping endpoint.
	resp, _, err := httpClient.Execute(req, http.Options{NoClustering: true})
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return responseSignature{}, "", false
		}
		return responseSignature{}, "", false
	}
	defer resp.Close()

	// A WAF/CDN block, auth gate, or rate-limit page — even one served with a 200
	// status — is not an LDAP result page. Treating it as a usable probe would let
	// the edge's content manufacture a wildcard-vs-control differential, so report it
	// as unusable (the boolean leg aborts rather than trusting the block body).
	if infra.IsBlockedResponse(resp) {
		return responseSignature{}, "", false
	}

	body := resp.Body().String()
	sig := newResponseSignature(resp.Response().StatusCode, body)
	full := resp.FullResponseString()
	return sig, full, true
}

// isAccessDenied returns true for status codes that indicate the request was
// rejected by an auth/WAF/rate-limit layer rather than served by the app.
func isAccessDenied(status int) bool {
	return status == 401 || status == 403 || status == 429 || status == 503
}

// isLDAPRelatedParam checks if a parameter name suggests LDAP involvement. Fixed
// standard request headers are excluded first: the short tokens below ("user", "dn",
// "ou", …) substring-match browser headers (User-Agent, DNT) that carry no LDAP
// query and only add noise/wasted probes if fuzzed with filter metacharacters.
func isLDAPRelatedParam(name string) bool {
	if infra.IsStandardRequestHeader(name) {
		return false
	}
	nameLower := strings.ToLower(name)
	for _, p := range ldapParamNames {
		if strings.Contains(nameLower, p) {
			return true
		}
	}
	return false
}

// containsLDAPError checks if the response body contains LDAP error indicators.
func containsLDAPError(body string) bool {
	bodyLower := strings.ToLower(body)
	for _, p := range ldapErrorPatterns {
		if strings.Contains(bodyLower, p) {
			return true
		}
	}
	return false
}

// findLDAPError returns the first matching LDAP error pattern found in the body.
func findLDAPError(body string) string {
	bodyLower := strings.ToLower(body)
	for _, p := range ldapErrorPatterns {
		if strings.Contains(bodyLower, p) {
			return p
		}
	}
	return ""
}
