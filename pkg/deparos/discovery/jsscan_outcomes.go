package discovery

import (
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
	"github.com/vigolium/vigolium/pkg/deparos/storage"
)

// Template outcomes say what became of each JS-derived request template by the
// time a target's crawl stops. Only replayed_found used to leave a trace (a
// siteMap node); everything else vanished with the ephemeral siteMap, so a JS
// endpoint that answered 404, was medium confidence, or was a withheld POST was
// invisible to every later phase. The integrated source reads these through
// Engine.RequestTemplateOutcomes and persists each one as a request stub.
const (
	TemplateReplayedFound      = "replayed_found"      // replayed; the Analyzer judged it to exist
	TemplateReplayedNotFound   = "replayed_not_found"  // replayed; 404, a request-shape 4xx, or soft-404
	TemplateWithheldPolicy     = "withheld_policy"     // never sent: replay_safety, a WS/SSE method, or replay_mode off
	TemplateWithheldConfidence = "withheld_confidence" // never sent: below the replay_mode confidence floor
	TemplateWithheldFlushCap   = "withheld_flush_cap"  // never sent: still pending when the flush cap or deadline hit
	TemplateOutOfScope         = "out_of_scope"        // outside the crawl scope; never sent and never persisted
	TemplateDeduped            = "deduped"             // the same request was already sent by another task
	TemplateUnresolvable       = "unresolvable"        // no candidate URL resolved to something sendable
)

// ReasonUnreplayed is the withheld_flush_cap reason for a template that was
// still pending when the crawl ended.
const ReasonUnreplayed = "unreplayed"

// Bounds on the response evidence kept for replayed templates. The body is
// what makes a persisted 404 row useful (it shows what the route answered), but
// it is held in memory until the target's crawl ends, so both the per-response
// and the per-engine totals are capped. Past the total, status and headers are
// still kept.
const (
	maxReplayEvidenceBody  = 64 * 1024
	maxReplayEvidenceTotal = 32 * 1024 * 1024
)

// ReplayNote is one observation about a template: the outcome and, for a
// replayed one, the request actually sent and what came back.
type ReplayNote struct {
	Outcome string
	// Reason refines the outcome: "method:POST", "graphql-mutation",
	// "metadata-only", "replay-off", the confidence ("medium"/"low"),
	// "unreplayed", "build-error", "analysis-error".
	Reason string
	Status int
	Method string
	URL    string
	// Response is the captured evidence for a replayed outcome (body capped at
	// maxReplayEvidenceBody). nil for anything that was never sent.
	Response *storage.ResponseData
}

// TemplateOutcome is a template plus its final note.
type TemplateOutcome struct {
	Template ExtractedRequestTemplate
	ReplayNote
}

// Replayed reports whether the template was actually sent.
func (o TemplateOutcome) Replayed() bool {
	return o.Outcome == TemplateReplayedFound || o.Outcome == TemplateReplayedNotFound
}

// outcomeRank orders notes by how much they say about the endpoint. A template
// can be noted once per variant (up to three candidate URLs) and once per flush
// round; the strongest observation wins.
func outcomeRank(outcome string) int {
	switch outcome {
	case TemplateReplayedFound:
		return 8
	case TemplateReplayedNotFound:
		return 7
	case TemplateDeduped:
		return 6
	case TemplateOutOfScope:
		return 5
	case TemplateUnresolvable:
		return 4
	case TemplateWithheldPolicy:
		return 3
	case TemplateWithheldConfidence:
		return 2
	case TemplateWithheldFlushCap:
		return 1
	default:
		return 0
	}
}

// supersedes reports whether n should replace an existing note. Between two
// not-found replays, a status other than 404 says more (400/405/415/422 mean
// the route exists and wants something), so it wins over a 404.
func (n ReplayNote) supersedes(existing ReplayNote) bool {
	nr, er := outcomeRank(n.Outcome), outcomeRank(existing.Outcome)
	if nr != er {
		return nr > er
	}
	if n.Outcome == TemplateReplayedNotFound && existing.Status == 404 && n.Status != 404 && n.Status > 0 {
		return true
	}
	return false
}

// TemplateStub is the request a template stands for, rendered the same way a
// replay would render it but without sending anything.
type TemplateStub struct {
	Method string
	// MethodUnresolved is set when the fact's method was empty or templated and
	// the stub fell back to GET.
	MethodUnresolved bool
	URL              string
	Headers          []string
	Body             string
	ContentType      string
}

// BuildTemplateStub renders a template into a request stub: the first candidate
// URL that resolves (against the application origin, as replay does), the
// rendered query, the safe headers only (sensitive and browser-controlled ones
// are stripped exactly as for replay) and the body with variables substituted.
// fallback supplies the origin when the template's source URL has none.
func BuildTemplateStub(template ExtractedRequestTemplate, fallback *url.URL) (TemplateStub, bool) {
	fact := &template.Request
	stub := TemplateStub{Method: strings.ToUpper(strings.TrimSpace(fact.Method.Rendered))}
	if stub.Method == "" || ContainsTemplateVar(stub.Method) {
		stub.Method = "GET"
		stub.MethodUnresolved = true
	}
	query := renderFactFields(fact.Query)
	for _, candidate := range append([]string{fact.URL.Rendered}, fact.URL.Alternatives...) {
		if resolved := resolveReplayURL(candidate, template.SourceURL, fallback); resolved != "" {
			stub.URL = mergeRenderedQuery(resolved, query)
			break
		}
	}
	if stub.URL == "" {
		return TemplateStub{}, false
	}
	stub.Headers = safeReplayHeaders(fact)
	if fact.Body != nil {
		stub.Body = ReplaceTemplateVars(fact.Body.Value.Rendered)
		stub.ContentType = fact.Body.ContentType
	}
	if stub.ContentType == "" {
		stub.ContentType = headerValue(stub.Headers, "Content-Type")
	}
	return stub, true
}

// captureReplayResponse copies what a replay got back into storage form,
// keeping at most maxReplayEvidenceBody of the body. Must run before rc.Close.
func captureReplayResponse(rc *responsechain.ResponseChain) *storage.ResponseData {
	if rc == nil || !rc.Has() {
		return nil
	}
	resp := rc.Response()
	if resp == nil {
		return nil
	}
	headers := make(map[string]string, len(resp.Header))
	for name, values := range resp.Header {
		if len(values) > 0 {
			headers[name] = values[0]
		}
	}
	full := rc.BodyBytes()
	body := full
	if len(body) > maxReplayEvidenceBody {
		body = body[:maxReplayEvidenceBody]
	}
	return &storage.ResponseData{
		StatusCode:    resp.StatusCode,
		Headers:       headers,
		Body:          append([]byte(nil), body...),
		ContentLength: int64(len(full)),
		MIMEType:      extractMIMEType(resp.Header.Get("Content-Type")),
		Location:      resp.Header.Get("Location"),
		DurationMs:    rc.Duration().Milliseconds(),
	}
}
