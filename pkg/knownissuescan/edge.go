package knownissuescan

import (
	"context"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// known-issue-scan is the one active phase whose traffic does NOT go through
// pkg/http.Requester: it runs projectdiscovery/nuclei as an in-process library,
// which owns its own HTTP stack. That left it outside everything the shared
// requester provides — per-host AIMD back-off on 429/503/5xx and connection
// errors, proactive pacing when a CDN/WAF edge is fingerprinted, and the
// [waf-block-detected] notice — with nothing but a flat global requests/second
// cap that (per the same report) was only applied when explicitly passed.
//
// The failure mode was silent and misleading in the worst possible direction: an
// unknown target opened at up to 100 rps with no way to slow down, the edge
// started filtering, and NOTHING reported it. The phase returned a thin surface
// indistinguishable from a clean target, so a consumer could not tell "there was
// nothing here" from "we were blocked in the first ten seconds".
//
// nuclei's SDK exposes no response hook and no runtime-adjustable limiter, so
// the fix is not a transport port. It is an edge sentinel that runs alongside
// the scan on the SHARED requester — the same object every other phase pages
// through, and therefore the same block detector, the same notifier and the same
// host limiter:
//
//   - Before the engine is built, every target host is probed once. Real
//     traffic through the real requester, so a block notice and a pre-arm fire
//     exactly as they would in discovery. Hosts that answer with a block are
//     DROPPED from the target list rather than scanned — the strongest available
//     form of "back off", and the safest: an edge that is already filtering
//     yields nothing but noise and rate-limit pressure.
//   - The post-probe per-host verdict drives nuclei's own concurrency and rate
//     knobs, so a pre-armed CDN host makes the phase open narrow instead of at
//     the flat default.
//   - While the scan runs, the sentinel re-probes on a ticker. A host that
//     starts filtering mid-run produces a block notice (and a waf.block event)
//     that the operator and a consumer both see, and consecutive blocks across
//     the target set curtail the phase instead of pushing through a wall of 403s.

// HostProbe sends one cheap request to rawURL through the scan's shared
// requester and reports whether the response was classified as a WAF/CDN block.
// The requester's own notifier and host-limiter feedback fire as a side effect —
// that is the point of routing through it rather than probing directly.
type HostProbe func(ctx context.Context, rawURL string) (blocked bool, err error)

// HostLimitReader reports the current per-host concurrency verdict for a host,
// which is what the limiter's proactive pacing has already decided. Supplied by
// the runner so this package does not depend on the limiter type.
type HostLimitReader func(host string) (limit int, ceiling int)

// Edge gathers the optional hooks that connect this phase to the scan's shared
// pacing infrastructure. All fields are optional: with none set the phase
// behaves exactly as it did before, minus the unbounded default rate.
type Edge struct {
	Probe        HostProbe
	HostLimit    HostLimitReader
	SentinelTick time.Duration
}

// sentinelInterval is how often the running scan re-probes its hosts.
//
// 30 seconds: frequent enough that a block is caught within a phase that
// typically runs minutes, and rare enough that the sentinel's own traffic is a
// rounding error next to nuclei's — a sentinel that itself contributes
// measurable load would be arming the WAF it exists to detect.
const sentinelInterval = 30 * time.Second

// preflightConcurrency bounds the pre-flight and sentinel probe sweeps.
//
// The probes are independent by construction — one per host, sharing only the
// requester, which is concurrency-safe and does its own per-host pacing. Run
// serially they are dead wall-clock time in front of the engine, worst exactly
// when the target is slow or filtering (every probe burns the full timeout);
// a scan that ran port-sweep can easily have dozens of host:port entries.
const preflightConcurrency = 8

// preflightHosts probes each distinct host behind targets and returns the
// targets worth scanning, plus the hosts that came back blocked.
//
// Probing per HOST rather than per target is deliberate: an enriched target list
// carries many paths per host, and a block is a property of the edge, not of the
// path. One probe per host bounds the pre-flight at a handful of requests.
func preflightHosts(ctx context.Context, targets []string, probe HostProbe) (keep []string, blocked []string) {
	if probe == nil || len(targets) == 0 {
		return targets, nil
	}
	byHost := groupTargetsByHost(targets)
	blockedSet := probeHosts(ctx, byHost, probe, preflightConcurrency)
	if len(blockedSet) == 0 {
		return targets, nil
	}

	keep = make([]string, 0, len(targets))
	for _, t := range targets {
		if h := hostOf(t); h != "" && blockedSet[h] {
			continue
		}
		keep = append(keep, t)
	}
	for host := range blockedSet {
		blocked = append(blocked, host)
	}
	sort.Strings(blocked)
	return keep, blocked
}

// probeHosts probes each host once, up to `limit` at a time, and returns the set
// that answered with a block.
//
// A probe ERROR is a transport failure, not a block: the requester has already
// fed it to the host limiter, and scanning the host is still the right call
// since nuclei retries on its own.
func probeHosts(ctx context.Context, byHost map[string]string, probe HostProbe, limit int) map[string]bool {
	var (
		mu      sync.Mutex
		blocked = map[string]bool{}
		wg      sync.WaitGroup
		sem     = make(chan struct{}, max(limit, 1))
	)
	for host, sample := range byHost {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(host, sample string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			isBlocked, err := probe(ctx, sample)
			if err != nil {
				zap.L().Debug("KnownIssueScan: edge probe failed",
					zap.String("host", host), zap.Error(err))
				return
			}
			if isBlocked {
				mu.Lock()
				blocked[host] = true
				mu.Unlock()
			}
		}(host, sample)
	}
	wg.Wait()
	return blocked
}

// pacedFor narrows concurrency and rate to what the host limiter has already
// decided for the scan's hosts. It takes the MINIMUM verdict across hosts: one
// invocation drives one nuclei engine, so the phase can only open as wide as its
// most constrained host allows without bursting that host.
func pacedFor(targets []string, read HostLimitReader, concurrency, rateLimit int) (int, int) {
	if read == nil || len(targets) == 0 {
		return concurrency, rateLimit
	}
	narrowest, ceiling := 0, 0
	for hostPort := range groupTargetsByHost(targets) {
		// The limiter is keyed by HOSTNAME (Service.Host() carries no port), while
		// the probe map is keyed by host:port so two services on one host are
		// probed separately. Strip the port for the lookup, or every target with
		// an explicit port misses and the pacing narrowing silently never applies.
		limit, hostCeiling := read(limiterKey(hostPort))
		if limit <= 0 {
			continue
		}
		if narrowest == 0 || limit < narrowest {
			narrowest, ceiling = limit, hostCeiling
		}
	}
	if narrowest <= 0 || ceiling <= 0 || narrowest >= ceiling {
		// No host has been paced below its ceiling — nothing to narrow to.
		return concurrency, rateLimit
	}
	// Scale both knobs by how far the limiter has backed the host off. Applying
	// the ratio rather than the absolute limit keeps the operator's own
	// --rate-limit meaningful: pacing narrows what they asked for, it does not
	// replace it.
	ratio := float64(narrowest) / float64(ceiling)
	return scaleAtLeastOne(concurrency, ratio), scaleAtLeastOne(rateLimit, ratio)
}

func scaleAtLeastOne(v int, ratio float64) int {
	if v <= 0 {
		return v
	}
	scaled := int(float64(v) * ratio)
	if scaled < 1 {
		return 1
	}
	return scaled
}

// sentinel re-probes the scan's hosts while it runs and cancels the scan when
// enough of them start filtering. Returns a stop func.
func (e Edge) sentinel(ctx context.Context, targets []string, cancel context.CancelFunc) func() {
	if e.Probe == nil || len(targets) == 0 {
		return func() {}
	}
	tick := e.SentinelTick
	if tick <= 0 {
		tick = sentinelInterval
	}
	byHost := groupTargetsByHost(targets)
	if len(byHost) == 0 {
		return func() {}
	}

	done := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(done) }) }

	go func() {
		ticker := time.NewTicker(tick)
		defer ticker.Stop()
		blocked := map[string]bool{}
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Only hosts not already known to be filtering. Probed in parallel
				// for the same reason as the pre-flight: a serial sweep that takes
				// longer than the tick leaves a fire pending the instant it
				// returns, so the sentinel would run back-to-back with no idle gap
				// — precisely when the edge is slow, which is when its own traffic
				// most needs to stay a rounding error.
				pending := map[string]string{}
				for host, sample := range byHost {
					if !blocked[host] {
						pending[host] = sample
					}
				}
				for host := range probeHosts(ctx, pending, e.Probe, preflightConcurrency) {
					blocked[host] = true
					zap.L().Warn("KnownIssueScan: edge is filtering; results for this host are incomplete",
						zap.String("host", host))
				}
				// A majority filtering means the run is producing nothing but
				// rate-limit pressure. One blocked host in a larger run is a reason
				// to have dropped that host, not to abandon the scan.
				if len(blocked)*2 >= len(byHost) {
					zap.L().Warn("KnownIssueScan: curtailing — a majority of target hosts are filtering scan traffic",
						zap.Int("blocked_hosts", len(blocked)), zap.Int("hosts", len(byHost)))
					cancel()
					return
				}
			}
		}
	}()
	return stop
}

// groupTargetsByHost maps each distinct host to one representative target URL.
// The representative is the shortest, which is the closest thing to a host root
// in an enriched list — the cheapest thing to probe and the least likely to be
// a path the edge treats specially.
func groupTargetsByHost(targets []string) map[string]string {
	out := make(map[string]string)
	for _, t := range targets {
		host := hostOf(t)
		if host == "" {
			continue
		}
		if prev, ok := out[host]; !ok || len(t) < len(prev) {
			out[host] = t
		}
	}
	return out
}

// hostOf keys the probe map: host WITH port, so two services on one hostname are
// probed (and blocked) independently.
func hostOf(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Host)
}

// limiterKey converts a probe-map key to the limiter's key, which is the bare
// hostname — pkg/http feeds it Service.Host(), and Service keeps the port in a
// separate field.
func limiterKey(hostPort string) string {
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		return h
	}
	return hostPort
}
