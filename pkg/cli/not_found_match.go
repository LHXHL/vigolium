package cli

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/deparos/fingerprint"
)

// notFoundMatcher answers "is this record the origin's not-found page?" from
// the baseline the fingerprint phase stored for its origin: a 404 or 410 is
// not-found by definition; any other answer is when its response matches every
// stable attribute of the baseline's signature. A record whose origin has no
// baseline has no answer.
//
// One lookup per distinct origin, memoized, like StoredHostFacts.
type notFoundMatcher struct {
	ctx         context.Context
	repo        *database.Repository
	projectUUID string
	memo        map[string]*fingerprint.Signature
	// available is false when the store has no host_observations table, so no
	// origin can have a baseline and nothing is looked up.
	available bool
}

func newNotFoundMatcher(ctx context.Context, db *database.DB, projectUUID string) *notFoundMatcher {
	if db == nil {
		return nil
	}
	repo := database.NewRepository(db)
	return &notFoundMatcher{ctx: ctx, repo: repo, projectUUID: projectUUID,
		memo: map[string]*fingerprint.Signature{}, available: repo.HasHostObservations(ctx)}
}

// Not-found verdict reasons: why a response is, or is not, its origin's
// not-found page. `match-not-found -j` publishes them verbatim.
const (
	notFoundReason404       = "status-404"  // a 404 is not-found by definition
	notFoundReason410       = "status-410"  // so is a 410
	notFoundReasonSignature = "signature"   // compared against the origin's baseline signature
	notFoundReasonNoBase    = "no-baseline" // the origin has no baseline to compare against
	notFoundReasonNoBody    = "no-body"     // a baseline exists, but there is no response to compare
)

// notFoundVerdict is one answer: whether the response is the origin's
// not-found page, whether that is known at all, and why.
type notFoundVerdict struct {
	matches, known bool
	reason         string
}

// notFoundResponse is one response to classify: a stored record's, or one a
// caller hands `match-not-found`.
type notFoundResponse struct {
	hostname string
	port     int
	url      *url.URL
	status   int
	// hasResponse is false when there is nothing to compare (a record without
	// a stored response, an item without a body).
	hasResponse bool
	// raw is a stored record's whole response, split into headers and body only
	// if the comparison gets that far. rawURL is parsed on the same terms. Most
	// records answer on the status alone or have no baseline, and a corpus-wide
	// pass over an export would otherwise copy a header block and parse a URL
	// for every one of them.
	raw     []byte
	rawURL  string
	headers http.Header
	body    []byte
}

// Matches reports (matches, known) for one record.
func (m *notFoundMatcher) Matches(rec *database.HTTPRecord) (bool, bool) {
	if m == nil || rec == nil {
		return false, false
	}
	v := m.classify(notFoundResponse{
		hostname: rec.Hostname, port: rec.Port, status: rec.StatusCode,
		hasResponse: rec.HasResponse && len(rec.RawResponse) > 0,
		raw:         rec.RawResponse, rawURL: rec.URL,
	})
	return v.matches, v.known
}

// classify is the one not-found decision, shared by the stored-record path
// (Matches: `traffic --fields matches_not_found`, `--exclude-not-found`) and
// `match-not-found`: a 404 or 410 is not-found; otherwise the response is
// compared with every stable attribute of its origin's baseline signature, and
// without a baseline (or a response) there is no answer.
func (m *notFoundMatcher) classify(r notFoundResponse) notFoundVerdict {
	switch r.status {
	case 404:
		return notFoundVerdict{matches: true, known: true, reason: notFoundReason404}
	case 410:
		return notFoundVerdict{matches: true, known: true, reason: notFoundReason410}
	}
	sig := m.signature(r.hostname, r.port)
	if sig == nil || sig.StableAttributeCount() == 0 {
		return notFoundVerdict{reason: notFoundReasonNoBase}
	}
	if !r.hasResponse {
		return notFoundVerdict{reason: notFoundReasonNoBody}
	}
	u, headers, body := r.url, r.headers, r.body
	if r.raw != nil {
		block, b := splitHeadersBody(r.raw)
		u, _ = url.Parse(r.rawURL)
		headers, body = parseHTTPHeaderBlock(block), b
	}
	sample := fingerprint.NewSampleFromParts(u, r.status, headers, body)
	return notFoundVerdict{matches: sig.Matches(sample), known: true, reason: notFoundReasonSignature}
}

// signature is the origin's stored baseline signature, nil when it has none.
// Memoized per origin, misses included.
func (m *notFoundMatcher) signature(hostname string, port int) *fingerprint.Signature {
	// No table means no origin can have a baseline, so nothing is looked up and
	// nothing is memoized - not even the key, which a corpus-wide pass would
	// otherwise build once per record for a map that stays empty.
	if m == nil || !m.available {
		return nil
	}
	key := strings.ToLower(hostname) + ":" + strconv.Itoa(port)
	sig, seen := m.memo[key]
	if !seen {
		nf, err := m.repo.LookupNotFoundBaseline(m.ctx, m.projectUUID, hostname, port)
		if err == nil && nf != nil && len(nf.Signature) > 0 {
			sig = fingerprint.SignatureFromNamed(nf.Signature)
		}
		m.memo[key] = sig
	}
	return sig
}

// parseHTTPHeaderBlock reads a stored header block into an http.Header.
func parseHTTPHeaderBlock(block string) http.Header {
	h := http.Header{}
	for _, e := range parseHeaderEntries(block) {
		h.Add(e.Name, e.Value)
	}
	return h
}
