package runner

import (
	"fmt"
	"maps"
	"net/url"
	"slices"
	"sync"

	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// authWallCollector gathers the login / SSO walls a phase's transport refused
// to follow into, so the phase can report them once at the end and feed their
// hosts into the scan-wide fuzz exclusion.
//
// It exists because the report is per-host but the signal is per-request: a
// sweep of one target behind Cloudflare Access produces a wall stop on every
// path probed, and printing each would bury the phase's real output. Callers
// wire Observe into core.ExecutorConfig.OnAuthWall, which the executor invokes
// from its worker goroutines — hence the lock.
type authWallCollector struct {
	mu sync.Mutex
	// walls maps wall host -> one example target that bounced to it. The
	// example is what makes the notice actionable: "supply --auth" is advice
	// nobody can act on without knowing which of 5,000 targets it applies to.
	walls map[string]string
}

func newAuthWallCollector() *authWallCollector {
	return &authWallCollector{walls: make(map[string]string)}
}

// Observe records one refused hop. Safe for concurrent use.
func (c *authWallCollector) Observe(target, wall string) {
	host := hostOfURL(wall)
	if host == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, seen := c.walls[host]; !seen {
		c.walls[host] = target
		zap.L().Info("Redirect stopped at a login/SSO wall",
			zap.String("target", target), zap.String("wall", wall))
	}
}

// Walls returns a snapshot of wall host -> example target. One locked call
// rather than a list accessor plus a per-host lookup, which took the lock once
// per wall to read a map the phase has already finished writing.
func (c *authWallCollector) Walls() map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return maps.Clone(c.walls)
}

// hostOfURL returns the bare lowercase hostname of raw, or "" when it does not
// parse as an absolute URL with a host. Port-stripped so the value matches the
// one spelling the SSO block list uses (see normalizeSSOHost) — this feeds the
// same list, and a host:port entry here silently failed to match the bare
// hostnames every other producer contributes.
func hostOfURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return normalizeSSOHost(u.Hostname())
}

// reportAuthWalls prints the phase's login-wall summary and feeds the wall
// hosts into the scan-wide fuzz exclusion the spidering phase also populates.
//
// Both halves matter and neither is redundant. The notice is the only place a
// headless run learns that its target is gated at all — the stored row is a
// bare 3xx, which reads identically to a target that simply moved. The
// exclusion stops a later phase from fuzzing the identity provider, which is
// somebody else's infrastructure and never the thing under test.
//
// A wall already known to the scan is fed but NOT re-announced. Every phase
// that fetches the target bounces off the same wall, so without this the same
// advice prints once per phase — and the advice is scan-wide, not per-phase.
// Reusing ssoHosts as the "already said" set also means a wall the browser
// crawler found is not repeated by the native phases, and vice versa.
//
// Callers hold no lock: this runs after the phase's executor has drained.
func (r *Runner) reportAuthWalls(phase string, c *authWallCollector) {
	walls := c.Walls()
	if len(walls) == 0 {
		return
	}

	var fresh []string
	// Sorted so the output is stable across runs.
	for _, host := range slices.Sorted(maps.Keys(walls)) {
		if slices.Contains(r.spidering.ssoHosts, host) {
			continue
		}
		fresh = append(fresh, host)
		r.printPhaseDetail(fmt.Sprintf("%s %s is behind a login/SSO wall at %s — the redirect was not followed, so only the %s is recorded. Supply authentication (%s) to scan behind it.",
			terminal.Yellow(terminal.SymbolArrow),
			terminal.Gray(walls[host]),
			terminal.Yellow(host),
			terminal.Gray("3xx"),
			terminal.BoldCyan("--auth")))
	}
	if len(fresh) == 0 {
		return
	}
	r.feedReSpiderSSOHosts(fresh)
	zap.L().Info(phase+": redirects stopped at login/SSO wall(s)",
		zap.Strings("hosts", fresh))
}
