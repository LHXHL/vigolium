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

// Matches reports (matches, known) for one record.
func (m *notFoundMatcher) Matches(rec *database.HTTPRecord) (bool, bool) {
	if m == nil || rec == nil {
		return false, false
	}
	if rec.StatusCode == 404 || rec.StatusCode == 410 {
		return true, true
	}
	key := strings.ToLower(rec.Hostname) + ":" + strconv.Itoa(rec.Port)
	sig, seen := m.memo[key]
	if !seen && m.available {
		nf, err := m.repo.LookupNotFoundBaseline(m.ctx, m.projectUUID, rec.Hostname, rec.Port)
		if err == nil && nf != nil && len(nf.Signature) > 0 {
			sig = fingerprint.SignatureFromNamed(nf.Signature)
		}
		m.memo[key] = sig
	}
	if sig == nil || sig.StableAttributeCount() == 0 {
		return false, false
	}
	if !rec.HasResponse || len(rec.RawResponse) == 0 {
		return false, false
	}
	headers, body := splitHeadersBody(rec.RawResponse)
	u, _ := url.Parse(rec.URL)
	sample := fingerprint.NewSampleFromParts(u, rec.StatusCode, parseHTTPHeaderBlock(headers), body)
	return sig.Matches(sample), true
}

// parseHTTPHeaderBlock reads a stored header block into an http.Header.
func parseHTTPHeaderBlock(block string) http.Header {
	h := http.Header{}
	for _, e := range parseHeaderEntries(block) {
		h.Add(e.Name, e.Value)
	}
	return h
}
