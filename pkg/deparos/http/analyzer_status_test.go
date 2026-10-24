package http

import (
	"context"
	"net/http"
	"testing"

	"github.com/vigolium/vigolium/pkg/deparos/fingerprint"
	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
)

// TestAnalyze_RequestShapeRejectionsNotFound verifies the status gate: request
// shape rejections (400/414/421/431) are treated as "not found" (the origin
// refused to route by shape — no resource), while 405 and auth/forbidden/error
// statuses still count as existing (they flow to the dedup-layer status policy).
func TestAnalyze_RequestShapeRejectionsNotFound(t *testing.T) {
	analyzer := NewAnalyzer(nil) // no comparator → status logic only
	ctx := context.Background()
	req, _ := http.NewRequest("GET", "https://example.com/x", nil)

	cases := []struct {
		status int
		want   bool
	}{
		{400, false}, // e.g. Jetty "Ambiguous URI empty segment"
		{414, false}, // URI too long
		{421, false}, // misdirected request
		{431, false}, // request headers too large
		{404, false}, // not found (pre-existing)
		{405, true},  // method not allowed → path exists
		{200, true},
		{401, true}, // auth wall → kept for the dedup-layer policy
		{403, true}, // forbidden → kept for the dedup-layer policy
		{410, true}, // gone → kept (it was there)
		{500, true}, // error surface
	}
	for _, tc := range cases {
		rc := createTestResponseChainFromParts(tc.status, nil, "body")
		found, err := analyzer.Analyze(ctx, req, rc)
		rc.Close()
		if err != nil {
			t.Fatalf("status %d: unexpected err %v", tc.status, err)
		}
		if found != tc.want {
			t.Errorf("status %d: got found=%v, want %v", tc.status, found, tc.want)
		}
	}
}

// countingComparator records how often the analyzer consulted it.
type countingComparator struct{ calls int }

func (c *countingComparator) Compare(context.Context, *http.Request, *responsechain.ResponseChain) (fingerprint.MatchResult, error) {
	c.calls++
	return fingerprint.TruePositive, nil
}

// Hard negatives are decided by status alone: the comparator (an HTML parse,
// a full-body hash, and for an unmatched 400 a 4-probe wildcard validation)
// must not run for a verdict it cannot change.
func TestAnalyze_HardNegativesSkipComparator(t *testing.T) {
	ctx := context.Background()
	req, _ := http.NewRequest("GET", "https://example.com/x", nil)
	for _, tc := range []struct {
		status    int
		wantFound bool
		wantCalls int
	}{
		{404, false, 0},
		{400, false, 0},
		{414, false, 0},
		{421, false, 0},
		{431, false, 0},
		{200, true, 1},
		{403, true, 1},
		{405, true, 1},
	} {
		cmp := &countingComparator{}
		rc := createTestResponseChainFromParts(tc.status, nil, "body")
		found, err := NewAnalyzerWithComparator(cmp).Analyze(ctx, req, rc)
		rc.Close()
		if err != nil {
			t.Fatalf("status %d: %v", tc.status, err)
		}
		if found != tc.wantFound || cmp.calls != tc.wantCalls {
			t.Errorf("status %d: found=%v comparator calls=%d, want found=%v calls=%d",
				tc.status, found, cmp.calls, tc.wantFound, tc.wantCalls)
		}
	}
}
