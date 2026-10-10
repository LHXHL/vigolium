package graphql_scan

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/graphqlx"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// csrfForeignOrigin is the attacker origin stamped on forged cross-site POSTs.
// The .invalid TLD never resolves, so nothing is ever sent there.
const csrfForeignOrigin = "https://graphql-csrf-probe.invalid"

// maxCSRFOps caps how many operations are tried to find one whose result depends
// on the session cookie.
const maxCSRFOps = 3

// csrfOp is one GraphQL operation replayed through the forgeable transports.
type csrfOp struct {
	query         string
	operationName string
	variables     json.RawMessage
	source        string // "observed request" or "schema"
}

// jsonBody renders the operation as the standard JSON POST body.
func (op csrfOp) jsonBody() string {
	body := map[string]any{"query": op.query}
	if op.operationName != "" {
		body["operationName"] = op.operationName
	}
	if len(op.variables) > 0 && string(op.variables) != "null" {
		body["variables"] = op.variables
	}
	b, _ := json.Marshal(body)
	return string(b)
}

// formValues renders the operation as the parameters a cross-site HTML form or
// a top-level GET navigation can carry.
func (op csrfOp) formValues() url.Values {
	v := url.Values{"query": {op.query}}
	if op.operationName != "" {
		v.Set("operationName", op.operationName)
	}
	if len(op.variables) > 0 && string(op.variables) != "null" {
		v.Set("variables", string(op.variables))
	}
	return v
}

// isMutation reports whether a GraphQL document is a mutation (or subscription)
// rather than a read-only query.
func isMutation(query string) bool {
	q := strings.TrimSpace(query)
	for strings.HasPrefix(q, "#") { // leading comment lines
		if i := strings.IndexByte(q, '\n'); i >= 0 {
			q = strings.TrimSpace(q[i+1:])
		} else {
			return false
		}
	}
	lower := strings.ToLower(q)
	return strings.HasPrefix(lower, "mutation") || strings.HasPrefix(lower, "subscription")
}

// csrfVector is one cross-site-forgeable request shape: a top-level GET
// navigation, or an HTML form POST (urlencoded or text/plain). None of them
// needs a CORS preflight, so a browser sends them cross-site with ambient
// cookies.
type csrfVector struct {
	name        string
	method      string
	contentType string
	// postTransport marks a POST shape: mutations travel over it, whereas the
	// GraphQL-over-HTTP spec forbids mutations over GET.
	postTransport bool
	build         func(endpointPath string, op csrfOp) (path, body string)
}

var csrfVectors = []csrfVector{
	{
		name: "GET ?query=", method: "GET",
		build: func(endpointPath string, op csrfOp) (string, string) {
			sep := "?"
			if strings.Contains(endpointPath, "?") {
				sep = "&"
			}
			return endpointPath + sep + op.formValues().Encode(), ""
		},
	},
	{
		name: "POST application/x-www-form-urlencoded", method: "POST",
		contentType: "application/x-www-form-urlencoded", postTransport: true,
		build: func(endpointPath string, op csrfOp) (string, string) {
			return endpointPath, op.formValues().Encode()
		},
	},
	{
		name: "POST text/plain", method: "POST",
		contentType: "text/plain", postTransport: true,
		build: func(endpointPath string, op csrfOp) (string, string) {
			return endpointPath, op.jsonBody()
		},
	},
}

// gqlData extracts data from a successful GraphQL response (no errors, non-null
// data) and normalizes it so per-request dynamic tokens do not make two
// executions of the same operation look different.
func gqlData(r *gqlResp) (string, bool) {
	if r == nil || r.blocked || r.status < 200 || r.status >= 300 {
		return "", false
	}
	var resp struct {
		Data   json.RawMessage `json:"data"`
		Errors json.RawMessage `json:"errors"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(r.body)), &resp); err != nil {
		return "", false
	}
	if errs := strings.TrimSpace(string(resp.Errors)); errs != "" && errs != "null" && errs != "[]" {
		return "", false
	}
	data := strings.TrimSpace(string(resp.Data))
	if data == "" || data == "null" || data == "{}" {
		return "", false
	}
	return modkit.NormalizeForRatio(data, ""), true
}

// browserForgeableRaw strips everything a cross-site attacker page cannot make
// the victim's browser send — credential headers (Authorization, API keys, the
// captured Cookie) and custom X-* / Apollo preflight headers — then re-adds only
// the ambient session cookie (when cookie is non-empty).
func browserForgeableRaw(raw []byte, cookie string) ([]byte, error) {
	clean, err := modkit.StripCredentialHeaders(raw)
	if err != nil {
		return nil, err
	}
	for _, h := range httpmsg.NewHttpRequest(clean).Headers() {
		name := strings.ToLower(strings.TrimSpace(h.Name))
		if strings.HasPrefix(name, "x-") || name == "apollo-require-preflight" ||
			name == "origin" || name == "referer" {
			if clean, err = httpmsg.RemoveHeader(clean, h.Name); err != nil {
				return nil, err
			}
		}
	}
	if cookie != "" {
		return httpmsg.AddOrReplaceHeader(clean, "Cookie", cookie)
	}
	return clean, nil
}

// sendCSRF shapes and sends one probe through the credential-free requester, so
// the request's Cookie header is its only credential.
func (m *Module) sendCSRF(
	ctx *httpmsg.HttpRequestResponse,
	anon *http.Requester,
	method, path, contentType, body, cookie string,
	crossSite bool,
) (*gqlResp, string, bool) {
	raw, err := buildRaw(ctx, method, path, contentType, body)
	if err != nil {
		return nil, "", false
	}
	if contentType == "" {
		if raw, err = httpmsg.RemoveHeader(raw, "Content-Type"); err != nil {
			return nil, "", false
		}
	}
	if raw, err = browserForgeableRaw(raw, cookie); err != nil {
		return nil, "", false
	}
	if crossSite {
		if method != "GET" {
			raw, _ = httpmsg.AddOrReplaceHeader(raw, "Origin", csrfForeignOrigin)
		}
		raw, _ = httpmsg.AddOrReplaceHeader(raw, "Referer", csrfForeignOrigin+"/")
	}
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, err := anon.Execute(req, http.Options{NoClustering: true, NoRedirects: true})
	if err != nil {
		return nil, "", false
	}
	defer resp.Close()
	out := &gqlResp{body: resp.BodyString(), blocked: infra.IsBlockedResponse(resp)}
	if r := resp.Response(); r != nil {
		out.status = r.StatusCode
		out.ctype = r.Header.Get("Content-Type")
	}
	return out, string(raw), true
}

// csrfOperations collects the operations to replay: the observed request's own
// GraphQL operation first (mutations only under a deep scan, since replaying one
// changes state), then argless schema queries.
func csrfOperations(ctx *httpmsg.HttpRequestResponse, schema *graphqlx.Schema, deep bool) []csrfOp {
	var ops []csrfOp
	if req := ctx.Request(); req != nil {
		var observed struct {
			Query         string          `json:"query"`
			OperationName string          `json:"operationName"`
			Variables     json.RawMessage `json:"variables"`
		}
		if body := strings.TrimSpace(req.BodyToString()); strings.HasPrefix(body, "{") &&
			json.Unmarshal([]byte(body), &observed) == nil && strings.TrimSpace(observed.Query) != "" &&
			(deep || !isMutation(observed.Query)) {
			ops = append(ops, csrfOp{
				query: observed.Query, operationName: observed.OperationName,
				variables: observed.Variables, source: "observed request",
			})
		}
	}
	for _, op := range graphqlx.BuildOperations(schema, graphqlx.BuildOptions{OnlyArgless: true, MaxOperations: maxCSRFOps}) {
		if len(ops) >= maxCSRFOps {
			break
		}
		if op.Kind == graphqlx.KindQuery {
			ops = append(ops, csrfOp{query: op.Query, source: "schema"})
		}
	}
	return ops
}

// csrfCookiePosture decides whether the request's session cookie would be sent
// on a cross-site request. blocked means a session cookie is SameSite=Strict or
// Lax (the browser withholds it on cross-site POSTs, so no finding); observed
// means a Set-Cookie for a session cookie was seen and carried neither.
func csrfCookiePosture(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) (blocked, observed bool, sessionCookies []string) {
	names := modkit.RequestCookieNames(ctx.Request().Header("Cookie"))
	for _, n := range names {
		if modkit.LikelySessionCookie(n) {
			sessionCookies = append(sessionCookies, n)
		}
	}
	// No recognizably named session cookie: any cookie may be the authenticator.
	relevant := sessionCookies
	if len(relevant) == 0 {
		relevant = names
	}
	isRelevant := make(map[string]bool, len(relevant))
	for _, n := range relevant {
		isRelevant[strings.ToLower(n)] = true
	}

	scanCtx.ObserveResponseCookies(ctx)
	for _, policy := range scanCtx.RequestCookiePolicies(ctx) {
		if !isRelevant[strings.ToLower(policy.Name)] {
			continue
		}
		if policy.SameSite == "strict" || policy.SameSite == "lax" {
			return true, true, relevant
		}
		observed = true
	}
	return false, observed, relevant
}

// phaseCSRF checks whether a cookie-authenticated GraphQL operation can be
// triggered cross-site. The endpoint must execute the same operation, with the
// same result, when it arrives as a top-level GET (?query=) or as an HTML form
// POST (urlencoded or text/plain) — shapes a browser sends cross-site with the
// victim's cookies and without a CORS preflight — and the session cookie must
// not be SameSite=Strict/Lax.
//
// Controls: the operation must succeed as a JSON POST carrying only the session
// cookie, and must NOT return the same data without it (otherwise it is public
// and there is nothing to forge). Every accepted vector is reconfirmed.
func (m *Module) phaseCSRF(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
	endpointPath string,
	schema *graphqlx.Schema,
	target string,
) *output.ResultEvent {
	if ctx.Request() == nil {
		return nil
	}
	cookie := strings.TrimSpace(ctx.Request().Header("Cookie"))
	if cookie == "" {
		return nil
	}
	blocked, postureObserved, sessionCookies := csrfCookiePosture(ctx, scanCtx)
	if blocked {
		return nil
	}
	anon, err := httpClient.CloneWithoutCredentials()
	if err != nil {
		return nil
	}
	deep := scanCtx != nil && scanCtx.DeepScan

	for _, op := range csrfOperations(ctx, schema, deep) {
		ref, _, ok := m.sendCSRF(ctx, anon, "POST", endpointPath, "application/json", op.jsonBody(), cookie, false)
		if !ok {
			continue
		}
		refData, ok := gqlData(ref)
		if !ok {
			continue // the operation does not succeed with the cookie alone
		}
		ctrl, _, ok := m.sendCSRF(ctx, anon, "POST", endpointPath, "application/json", op.jsonBody(), "", false)
		if !ok {
			continue
		}
		if ctrlData, ok := gqlData(ctrl); ok && ctrlData == refData {
			continue // same data without the cookie: not cookie-authenticated
		}

		var accepted []csrfVector
		var evidenceReq, evidenceResp string
		for _, vec := range csrfVectors {
			if !vec.postTransport && isMutation(op.query) {
				continue // mutations over GET are forbidden by spec; don't replay one
			}
			path, body := vec.build(endpointPath, op)
			var lastReq, lastBody string
			if !confirmRounds(defaultConfirmRounds, func() (bool, error) {
				r, raw, ok := m.sendCSRF(ctx, anon, vec.method, path, vec.contentType, body, cookie, true)
				if !ok {
					return false, nil
				}
				data, ok := gqlData(r)
				lastReq, lastBody = raw, r.body
				return ok && data == refData, nil
			}) {
				continue
			}
			accepted = append(accepted, vec)
			if evidenceReq == "" || vec.postTransport {
				evidenceReq, evidenceResp = lastReq, lastBody
			}
		}
		if len(accepted) == 0 {
			// This operation is cookie-authenticated and every forgeable shape was
			// refused: the endpoint is not CSRF-able through it. One cookie-bound
			// operation is representative of the transport, so stop here.
			return nil
		}
		return csrfResult(target, endpointPath, op, accepted, sessionCookies, postureObserved, evidenceReq, evidenceResp)
	}
	return nil
}

// csrfResult builds the event. It is a finding only when a POST transport
// (which carries mutations) was accepted AND the session cookie's observed
// Set-Cookie lacks SameSite=Strict/Lax. GET-only acceptance (mutations over GET
// are forbidden by spec, and only a query was replayed) or an unobserved cookie
// posture stays a candidate.
func csrfResult(
	target, endpointPath string,
	op csrfOp,
	accepted []csrfVector,
	sessionCookies []string,
	postureObserved bool,
	evidenceReq, evidenceResp string,
) *output.ResultEvent {
	names := make([]string, 0, len(accepted))
	postAccepted := false
	for _, v := range accepted {
		names = append(names, v.name)
		postAccepted = postAccepted || v.postTransport
	}
	kind, grade := output.RecordKindCandidate, output.EvidenceGradeDifferential
	confidence := severity.Tentative
	if postAccepted && postureObserved {
		kind, grade = output.RecordKindFinding, output.EvidenceGradeBypass
		confidence = severity.Firm
	}
	posture := "session cookie Set-Cookie not observed in this scan (browser default applies)"
	if postureObserved {
		posture = "session cookie observed without SameSite=Strict/Lax"
	}

	return &output.ResultEvent{
		ModuleID:      ModuleID,
		RecordKind:    kind,
		EvidenceGrade: grade,
		DedupKey:      fmt.Sprintf("graphql-csrf|%s|%s", target, endpointPath),
		URL:           target,
		Matched:       target + endpointPath,
		Request:       evidenceReq,
		Response:      evidenceResp,
		ExtractedResults: []string{
			fmt.Sprintf("GraphQL endpoint: %s", endpointPath),
			fmt.Sprintf("Forgeable transports accepted: %s", strings.Join(names, ", ")),
			fmt.Sprintf("Operation (%s): %s", op.source, op.query),
			fmt.Sprintf("Session cookies: %s", strings.Join(sessionCookies, ", ")),
			fmt.Sprintf("Cookie posture: %s", posture),
		},
		Info: output.Info{
			Name: "GraphQL Cross-Site Request Forgery",
			Description: fmt.Sprintf(
				"The GraphQL endpoint executed a cookie-authenticated operation, returning the same data as the "+
					"JSON request, when it arrived as %s with a foreign Origin. These request shapes are sent "+
					"cross-site by a browser with the victim's cookies and without a CORS preflight, so an attacker "+
					"page can make a logged-in victim run operations (including mutations over the POST transports). "+
					"The same operation without the cookie did not return that data. Cookie posture: %s. Fix: accept "+
					"only application/json POSTs (or require a custom header such as Apollo's CSRF prevention), "+
					"set SameSite=Lax or Strict on session cookies, and add CSRF tokens for cookie-authenticated mutations.",
				strings.Join(names, " / "), posture),
			Severity:   severity.Medium,
			Confidence: confidence,
			Tags:       ModuleTags,
		},
		Metadata: map[string]any{
			"security_primitive":     "csrf",
			"accepted_transports":    names,
			"post_transport":         postAccepted,
			"samesite_observed":      postureObserved,
			"cookie_control_differs": true,
			"operation_source":       op.source,
			"confirmation_rounds":    defaultConfirmRounds,
		},
	}
}
