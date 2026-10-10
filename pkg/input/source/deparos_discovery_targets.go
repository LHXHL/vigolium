package source

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"go.uber.org/zap"
)

// Running several discovery targets at once.
//
// runDiscovery drives a bounded pool of targets. Two targets on the same
// host:port never run together: discovery is the heaviest traffic a scan sends
// to one origin, and both engines would share its rate budget, its WAF and its
// soft-404 behaviour while each believed it had them alone. The thread budget
// (DeparosDiscoveryConfig.Concurrency) is split across the targets that can
// actually run together, so going concurrent does not multiply the requests a
// phase has in flight.

const (
	// defaultDiscoveryTargetConcurrency is the pool width when nothing is set.
	defaultDiscoveryTargetConcurrency = 3
	// minDiscoveryTargetThreads is the floor of a target's thread share: below
	// it an engine spends more time on its own bookkeeping than on requests.
	minDiscoveryTargetThreads = 5
)

// targetConcurrency resolves the pool width for n targets.
func (c DeparosDiscoveryConfig) targetConcurrency(n int) int {
	return DiscoveryTargetConcurrency(c.TargetConcurrency, n)
}

// DiscoveryTargetConcurrency is how many of n targets discovery runs at once
// with discovery.target_concurrency set to configured (0 = default).
func DiscoveryTargetConcurrency(configured, n int) int {
	width := configured
	if width <= 0 {
		width = defaultDiscoveryTargetConcurrency
	}
	return max(1, min(width, n))
}

// splitDiscoveryThreads is one target's share of the phase's thread budget when
// active targets run together: max(5, total/active).
func splitDiscoveryThreads(total, active int) int {
	if active <= 1 {
		return total
	}
	return max(minDiscoveryTargetThreads, total/active)
}

// discoveryHostKey is the host:port a target is serialized on. The default port
// is filled in from the scheme so http://a and http://a:80 are one origin; a
// target that does not parse as a URL is its own key.
func discoveryHostKey(target string) string {
	u, err := url.Parse(strings.TrimSpace(target))
	if err != nil || u.Host == "" {
		return strings.TrimSpace(target)
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "http", "ws":
			port = "80"
		default:
			port = "443"
		}
	}
	return host + ":" + port
}

type targetThreadsKey struct{}

// withTargetThreads hands discoverTarget its thread share without widening the
// discoverFn test seam.
func withTargetThreads(ctx context.Context, threads int) context.Context {
	return context.WithValue(ctx, targetThreadsKey{}, threads)
}

// targetThreads is the thread share runDiscovery gave this target, or fallback
// when called outside it.
func targetThreads(ctx context.Context, fallback int) int {
	if threads, ok := ctx.Value(targetThreadsKey{}).(int); ok && threads > 0 {
		return threads
	}
	return fallback
}

// targetResult is one finished target.
type targetResult struct {
	target string
	key    string
	err    error
}

// runDiscovery runs deparos for every target through a bounded pool and pushes
// results to the channel.
//
// parentCtx is the working context Next derived from baseCtx, so cancelling the
// phase stops every running engine rather than letting each finish its full
// MaxDuration. runDiscovery owns releasing it. It records what it did and did
// not get to, because a run where every target failed used to be
// indistinguishable from a run that legitimately found nothing: a target that
// started counts as attempted (failed or not), one never started counts as
// skipped.
func (d *DeparosDiscoverySource) runDiscovery(parentCtx context.Context, cancel context.CancelFunc) {
	// Registered first so it runs last: a waiter on finished must not wake until
	// items is closed and the working context is released.
	defer close(d.finished)
	defer close(d.items)
	defer cancel()

	discover := d.discoverFn
	if discover == nil {
		discover = d.discoverTarget
	}

	targets := d.cfg.Targets
	width := d.cfg.targetConcurrency(len(targets))
	pending := make([]int, len(targets)) // indices into targets, in order
	keys := make([]string, len(targets))
	for i, target := range targets {
		pending[i] = i
		keys[i] = discoveryHostKey(target)
	}
	active := make(map[string]bool, width)
	results := make(chan targetResult, width)
	running := 0

	var (
		firstErr error
		failed   int
		stopping bool
	)
	stopped := func() bool {
		if parentCtx.Err() != nil {
			return true
		}
		select {
		case <-d.done:
			return true
		default:
			return false
		}
	}

	for len(pending) > 0 || running > 0 {
		if !stopping && stopped() {
			stopping = true
		}
		if stopping {
			// Nothing new starts once the phase is stopping; whatever never
			// started is skipped. Running targets are still joined below.
			d.noteSkipped(len(pending))
			pending = nil
		}
		for !stopping && running < width {
			pos := firstRunnable(pending, keys, active)
			if pos < 0 {
				break
			}
			idx := pending[pos]
			threads := splitDiscoveryThreads(d.cfg.Concurrency, min(width, runnableKeys(pending, keys, active)))
			pending = append(pending[:pos], pending[pos+1:]...)
			active[keys[idx]] = true
			running++
			go func(target, key string, threads int) {
				results <- targetResult{target: target, key: key, err: discover(withTargetThreads(parentCtx, threads), target)}
			}(targets[idx], keys[idx], threads)
		}
		if running == 0 {
			continue // stopping drained pending; the loop condition ends it
		}

		var res targetResult
		if stopping {
			res = <-results
		} else {
			select {
			case res = <-results:
			case <-parentCtx.Done():
				continue
			case <-d.done:
				continue
			}
		}
		running--
		delete(active, res.key)
		if res.err == nil {
			continue
		}
		// A cancelled parent means we stopped it, not that the target failed. It
		// WAS attempted, so it is neither failed nor skipped.
		if parentCtx.Err() != nil {
			continue
		}
		failed++
		if firstErr == nil {
			firstErr = res.err
		}
		d.noteTargetError(res.target, res.err)
		zap.L().Warn("deparos discovery failed for target",
			zap.String("target", res.target), zap.Error(res.err))
	}

	// Every target failing is a phase failure, not an empty result set. Anything
	// less is partial coverage, which the stats already describe.
	if failed > 0 && failed == len(targets) {
		d.mu.Lock()
		d.runErr = fmt.Errorf("deparos discovery failed for all %d target(s): %w", failed, firstErr)
		d.mu.Unlock()
	}
}

// firstRunnable returns the position in pending of the first target whose
// host:port is not already being discovered, or -1.
func firstRunnable(pending []int, keys []string, active map[string]bool) int {
	for pos, idx := range pending {
		if !active[keys[idx]] {
			return pos
		}
	}
	return -1
}

// runnableKeys counts the distinct host:ports among the running and pending
// targets: the most targets that could be in flight together right now, which
// is what the thread budget is divided by. Five pending targets on one host
// can only ever run one at a time, so each gets the whole budget.
func runnableKeys(pending []int, keys []string, active map[string]bool) int {
	distinct := make(map[string]struct{}, len(active)+len(pending))
	for key := range active {
		distinct[key] = struct{}{}
	}
	for _, idx := range pending {
		distinct[keys[idx]] = struct{}{}
	}
	return len(distinct)
}
