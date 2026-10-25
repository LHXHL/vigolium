package runner

import (
	"errors"
	"slices"
	"testing"

	"github.com/vigolium/vigolium/pkg/agent/recon"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/core/egress"
)

// Every executor reason for an unanswered item maps to a probe error kind, and
// the cause the executor reported is the error the report shows.
func TestFingerprintUnansweredKinds(t *testing.T) {
	cases := []struct {
		reason string
		cause  error
		kind   string
		msg    string
	}{
		{core.DropFetchError, errors.New("dial tcp: connection refused"), recon.ProbeErrNetwork, "dial tcp: connection refused"},
		{core.DropQuarantined, nil, recon.ProbeErrNetwork, "host quarantined as unresponsive"},
		{core.DropBudget, egress.ErrBudgetExhausted, recon.ProbeErrBudget, egress.ErrBudgetExhausted.Error()},
		{core.DropOutOfScope, nil, recon.ProbeErrScope, "refused by scope"},
		{core.DropBlocked, errors.New("cloudflare challenge"), recon.ProbeErrBlocked, "cloudflare challenge"},
		{core.SkipStaticFile, nil, recon.ProbeErrSkipped, "refused before the send (static_file)"},
	}
	for _, c := range cases {
		kind, err := fingerprintUnanswered(c.reason, c.cause)
		if kind != c.kind || err == nil || err.Error() != c.msg {
			t.Errorf("%s: got (%q, %v), want (%q, %q)", c.reason, kind, err, c.kind, c.msg)
		}
	}
}

// The retry runs at two workers per failing origin, never above the round's
// concurrency and never below one.
func TestFingerprintRetryWorkers(t *testing.T) {
	for _, c := range []struct{ workers, failing, want int }{
		{50, 1, 2}, {50, 4, 8}, {50, 40, 50}, {1, 3, 1}, {0, 0, 1},
	} {
		if got := fingerprintRetryWorkers(c.workers, c.failing); got != c.want {
			t.Errorf("fingerprintRetryWorkers(%d, %d) = %d, want %d", c.workers, c.failing, got, c.want)
		}
	}
}

// The probe's icon round asks each final origin once, reads the link from the
// first page that carried a body, and stores the answer on that origin and on
// every target whose sweep ended there.
func TestPlanProbeFavicons(t *testing.T) {
	c := newProbeFaviconCollector()
	// Mirrors Observe's grouping: the final response's endpoint seeds the
	// origin, the target's endpoint joins it, the first body wins.
	page := func(target string, tport int, origin, host string, port int, body string) {
		if _, seen := c.endpoints[origin]; !seen {
			c.origins = append(c.origins, origin)
			c.addEndpoint(origin, hostPort{host, port})
		}
		c.addEndpoint(origin, hostPort{target, tport})
		if _, have := c.body[origin]; !have && body != "" {
			c.body[origin] = body
		}
	}
	page("example.com", 443, "https://www.example.com", "www.example.com", 443, "")
	page("www.example.com", 443, "https://www.example.com", "www.example.com", 443, `<link rel="icon" href="/img/fav.png">`)
	page("other.test", 8080, "http://other.test:8080", "other.test", 8080, "<html>no link</html>")

	refs := c.plan()
	if len(refs) != 2 {
		t.Fatalf("refs = %+v, want one per origin", refs)
	}
	if refs[0].origin != "https://www.example.com" || refs[0].probe.Path != "/img/fav.png" {
		t.Errorf("first ref = %+v, want the linked icon on the final origin", refs[0])
	}
	if refs[1].probe.Path != "/favicon.ico" {
		t.Errorf("second ref = %+v, want /favicon.ico", refs[1])
	}
	eps := c.endpoints["https://www.example.com"]
	if len(eps) != 2 || !slices.Contains(eps, hostPort{"example.com", 443}) || !slices.Contains(eps, hostPort{"www.example.com", 443}) {
		t.Errorf("endpoints = %+v, want the final origin and the redirecting target", eps)
	}
}
