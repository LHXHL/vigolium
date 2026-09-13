package http

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

// TestAnonymousViewDoesNotShareResponseCache is the regression guard for the
// authorization-differential cache collision.
//
// computeClusterKey hashes the RAW request bytes, but the credential surface a
// credential-stripped view isolates (custom headers, cookie jar) is applied later
// in doRequest. When credentials arrive via -H or a carried browser session
// rather than in the captured bytes, the authenticated request and its anonymous
// twin are byte-identical — so without a per-view cache partition one served the
// other from cache, and an authz-differential module read authenticated ==
// unauthenticated.
func TestAnonymousViewDoesNotShareResponseCache(t *testing.T) {
	opts := types.DefaultOptions()
	// Credentials supplied by flag, NOT present in the request bytes below.
	opts.Headers = []string{"Authorization: Bearer secret"}
	r := newTestRequesterWithOpts(t, opts)
	view, err := r.CloneWithoutCredentials()
	if err != nil {
		t.Fatalf("CloneWithoutCredentials: %v", err)
	}

	svc := httpmsg.NewServiceSecure("target.test", 443, true)
	raw := []byte("GET /admin HTTP/1.1\r\nHost: target.test\r\n\r\n")
	input := httpmsg.NewHttpRequestResponse(httpmsg.NewHttpRequestWithService(svc, raw), nil)

	// Reproduce what ExecuteContext stamps before handing options to the clusterer.
	authedOpts := Options{}
	authedOpts.clusterScope = r.clusterScope
	anonOpts := Options{}
	anonOpts.clusterScope = view.clusterScope

	authedKey := computeClusterKey(input, authedOpts)
	anonKey := computeClusterKey(input, anonOpts)

	if authedKey == anonKey {
		t.Error("the authenticated request and its credential-stripped twin share a cache key; " +
			"one would be served the other's response")
	}
	if view.clusterScope == "" {
		t.Error("the anonymous view has no cache partition")
	}
	if r.clusterScope != "" {
		t.Errorf("the primary requester should have an empty scope, got %q", r.clusterScope)
	}
}

// Two anonymous views of one requester MUST share a partition. Modules call
// CloneWithoutCredentials inside ScanPerRequest — once per record — so a
// per-clone scope would hand every probe its own cache partition and silently
// disable clustering for that whole traffic class.
func TestAnonymousViewsShareOnePartition(t *testing.T) {
	r := newTestRequester(t)
	a, err := r.CloneWithoutCredentials()
	if err != nil {
		t.Fatalf("view a: %v", err)
	}
	b, err := r.CloneWithoutCredentials()
	if err != nil {
		t.Fatalf("view b: %v", err)
	}
	if a.clusterScope != b.clusterScope {
		t.Errorf("views of one requester must coalesce together: %q vs %q", a.clusterScope, b.clusterScope)
	}
	if a.clusterScope == r.clusterScope {
		t.Error("a view must still be partitioned away from its credential-bearing parent")
	}
}

// WithContext is a same-credential view, so it MUST keep sharing the cache —
// coalescing identical concurrent reads is the clusterer's whole purpose.
func TestWithContextKeepsCachePartition(t *testing.T) {
	r := newTestRequester(t)
	if got := r.WithContext(t.Context()).clusterScope; got != r.clusterScope {
		t.Errorf("WithContext changed the cache partition: %q vs %q", got, r.clusterScope)
	}
}
