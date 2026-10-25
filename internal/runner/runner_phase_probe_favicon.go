package runner

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/vigolium/vigolium/pkg/agent/recon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/zap"
)

// The probe's --favicon: after the sweep, one read per answering origin for its
// icon, hashed the way the fingerprint phase hashes it (recon.FaviconRequest and
// recon.IconFrom are shared, so the two phases' hashes agree), and stored as a
// host fact (host_observations.favicon). `vigolium hosts` lifts it to
// favicon_mmh3, and every record of the host carries it as `favicon` in
// `traffic -j` and the jsonl export.
//
// The icon is resolved against the page the sweep stored: the final response,
// so a target that redirects to www. gets the icon www. links. It is stored on
// that origin's endpoint and on every target endpoint whose sweep ended there,
// since the redirecting target's own records carry the target's host:port.
//
// The read goes through the executor (scope, rate limit, request budget,
// per-host slots) but is not stored as a record: a sweep's output is one row
// per target, and the icon's bytes are not what anyone reads — the hash is.
// Redirects are not followed, as in the fingerprint phase.

// probeFaviconPageCap bounds how much of an origin's page is kept to find its
// icon link: the link sits in <head>.
const probeFaviconPageCap = 256 << 10

// hostPort is one endpoint an origin's icon is stored on.
type hostPort struct {
	host string
	port int
}

// probeFaviconCollector groups the sweep's answers by the origin they finally
// came from, which is the shape the icon round wants: one read per origin,
// stored on every target endpoint whose sweep ended there. Observe is an
// ExecutorConfig.OnResponse callback, so it copies what it keeps out of the
// pooled response buffer.
type probeFaviconCollector struct {
	mu      sync.Mutex
	origins []string          // first seen first, so the plan is stable
	body    map[string]string // origin -> the first page that could carry an icon link
	// endpoints maps an origin to the endpoints its icon is stored on, with
	// known as the membership set: a thousand targets landing on one edge is
	// the normal case, and a linear scan per answer would be quadratic in them.
	endpoints map[string][]hostPort
	known     map[string]map[hostPort]bool
}

func newProbeFaviconCollector() *probeFaviconCollector {
	return &probeFaviconCollector{
		body:      map[string]string{},
		endpoints: map[string][]hostPort{},
		known:     map[string]map[hostPort]bool{},
	}
}

// Observe folds one answered sweep item into its origin's group.
func (c *probeFaviconCollector) Observe(item *work.WorkItem, rr *httpmsg.HttpRequestResponse) {
	if c == nil || item == nil || item.Request == nil || rr == nil {
		return
	}
	target, final := item.Request.Service(), rr.Service()
	resp := rr.Response()
	if target == nil || final == nil || resp == nil {
		return
	}
	host := strings.ToLower(final.Host())
	origin := buildOriginURL(final.Protocol(), host, final.Port())

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, seen := c.endpoints[origin]; !seen {
		c.origins = append(c.origins, origin)
		c.addEndpoint(origin, hostPort{host, final.Port()})
	}
	c.addEndpoint(origin, hostPort{strings.ToLower(target.Host()), target.Port()})
	// Only the first page per origin is read for its icon link, so only it is
	// copied: a sweep of thousands of targets behind one edge would otherwise
	// hold a page for each of them until the icon round.
	if _, have := c.body[origin]; have {
		return
	}
	if body := resp.Body(); len(body) > 0 && looksLikePage(resp, body) {
		c.body[origin] = string(body[:min(len(body), probeFaviconPageCap)]) // copies out of the pooled buffer
	}
}

// addEndpoint records one endpoint to store this origin's icon on. Caller holds
// the lock.
func (c *probeFaviconCollector) addEndpoint(origin string, ep hostPort) {
	seen := c.known[origin]
	if seen == nil {
		seen = map[hostPort]bool{}
		c.known[origin] = seen
	}
	if seen[ep] {
		return
	}
	seen[ep] = true
	c.endpoints[origin] = append(c.endpoints[origin], ep)
}

// plan is one icon read per origin the sweep reached, in first-seen order: the
// icon the origin's page links, or /favicon.ico when it linked none.
func (c *probeFaviconCollector) plan() []fingerprintProbeRef {
	refs := make([]fingerprintProbeRef, 0, len(c.origins))
	for _, origin := range c.origins {
		u, err := url.Parse(origin)
		if err != nil || u.Host == "" {
			continue
		}
		refs = append(refs, fingerprintProbeRef{origin: origin, probe: recon.FaviconRequest(u, c.body[origin])})
	}
	return refs
}

// looksLikePage reports whether a response can carry an icon link: HTML by its
// Content-Type, or a body that opens like markup when the type is missing
// (isHTMLContentType answers "" with "let the body decide").
func looksLikePage(resp *httpmsg.HttpResponse, body []byte) bool {
	ct := resp.Header("Content-Type")
	if !isHTMLContentType(ct) {
		return false
	}
	if ct != "" {
		return true
	}
	trimmed := strings.TrimLeft(string(body[:min(len(body), 64)]), " \t\r\n")
	return strings.HasPrefix(trimmed, "<")
}

// probeFaviconReads sends the icon reads without storing them as records and
// without passive modules: the hash is the fact kept.
var probeFaviconReads = readsConfig{phase: PhaseProbe}

// runProbeFavicons fetches and stores the icon of every origin the sweep
// reached. It returns how many origins were asked and how many served an icon.
func (r *Runner) runProbeFavicons(ctx context.Context, infra *phaseInfra, workers int, favicons *probeFaviconCollector) (asked, found int, err error) {
	refs := favicons.plan()
	if len(refs) == 0 {
		return 0, 0, nil
	}
	results, err := r.executeReads(ctx, infra, probeFaviconReads, workers, refs)
	if err != nil {
		return len(refs), 0, err
	}
	var inputs []database.HostObservationInput
	for i, ref := range refs {
		icon := recon.IconFrom(ref.origin, &results[i])
		if icon == nil {
			if results[i].Err != nil {
				zap.L().Debug("Probe: icon read unanswered", zap.String("origin", ref.origin),
					zap.String("kind", results[i].ErrKind), zap.Error(results[i].Err))
			}
			continue
		}
		found++
		for _, ep := range favicons.endpoints[ref.origin] {
			inputs = append(inputs, database.HostObservationInput{
				Hostname: ep.host, Port: ep.port, HostFacts: database.HostFacts{Favicon: icon}, Complete: ctx.Err() == nil,
			})
		}
	}
	r.persistHostObservations(ctx, infra.scanUUID, inputs, "Probe: failed to persist favicons")
	return len(refs), found, nil
}

// probeFaviconSummary is the phase line the icon round prints.
func probeFaviconSummary(asked, found int) string {
	return fmt.Sprintf("Favicon: %s of %s origins serve an icon %s",
		terminal.Orange(fmt.Sprintf("%d", found)), terminal.HiTeal(fmt.Sprintf("%d", asked)),
		terminal.Gray("(read with 'vigolium hosts', field favicon_mmh3)"))
}
