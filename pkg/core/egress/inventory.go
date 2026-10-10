package egress

import "github.com/vigolium/vigolium/pkg/scanevents"

// inventoryEntry is one outbound path of a native scan. phases names the scan
// phases that use it; an empty list means "whenever the scan reaches a target".
type inventoryEntry struct {
	path   string
	reason string // exempt paths only
	phases []string
}

// gatedPaths go through a Gate: global rate token, host slot, quarantine,
// wire-attempt count.
var gatedPaths = []inventoryEntry{
	// Modules, executor fetches, seed, heuristics, probe, JS extensions — every
	// pkg/http.Requester send, one token per wire attempt (retries and redirect
	// hops included).
	{path: "http-requester"},
	// The deparos engine: its own token bucket (discovery.rate_limit, global
	// across concurrent discovery targets) plus the shared host slots and
	// quarantine.
	{path: "discovery", phases: []string{"discovery"}},
	// Session login flows, on the priority lane.
	{path: "login"},
	// The HTTP confirm step; the TCP pre-filter dials are counted, not paced.
	{path: "port-sweep", phases: []string{"port-sweep"}},
	// tls_cert_recon and tls_protocol_cipher_audit: one gated attempt per
	// handshake.
	{path: "tls-modules", phases: []string{"dynamic-assessment"}},
}

// exemptPaths bypass the gate. Listed so a consumer of scan.started can see
// exactly which traffic --rate-limit and max-per-host do not govern.
var exemptPaths = []inventoryEntry{
	{path: "known-issue-scan", reason: "own HTTP stack (nuclei): its own rate and concurrency apply, not the shared host slots or quarantine",
		phases: []string{"known-issue-scan"}},
	{path: "spidering", reason: "browser (Chrome): requests are counted, not gated",
		phases: []string{"spidering", "targeted-respider"}},
	{path: "browser-confirmations", reason: "browser (Chrome) used by confirmation modules: low volume, not gated or counted",
		phases: []string{"dynamic-assessment"}},
	{path: "http_request_smuggling.cl0", reason: "own dialer (raw socket): bypasses --proxy, the rate limit and host slots",
		phases: []string{"dynamic-assessment"}},
	{path: "h2race", reason: "own dialer (HTTP/2 single-packet race): honours an http:// CONNECT proxy, not the rate limit or host slots",
		phases: []string{"dynamic-assessment"}},
	{path: "probe-tls", reason: "own dialer: one TLS handshake per host:port for certificate metadata, cached",
		phases: []string{"probe"}},
	{path: "scheme-detection", reason: "bare TCP connect to choose http or https for a schemeless target",
		phases: []string{"probe"}},
	{path: "external-harvest", reason: "not target traffic: archive services only",
		phases: []string{"external-harvest"}},
	{path: "oast", reason: "not target traffic: the out-of-band interaction server"},
	{path: "npm-registry", reason: "not target traffic: dependency_confusion registry lookups",
		phases: []string{"dynamic-assessment"}},
}

// Inventory returns the scan.started egress table for a scan that runs the
// given phases (canonical phase ids). A nil list includes every path.
func Inventory(phases []string) *scanevents.Egress {
	var planned map[string]bool
	if phases != nil {
		planned = make(map[string]bool, len(phases))
		for _, p := range phases {
			planned[p] = true
		}
	}
	applies := func(e inventoryEntry) bool {
		if planned == nil || len(e.phases) == 0 {
			return true
		}
		for _, p := range e.phases {
			if planned[p] {
				return true
			}
		}
		return false
	}
	out := &scanevents.Egress{Gated: []string{}, Exempt: []scanevents.EgressExemption{}}
	for _, e := range gatedPaths {
		if applies(e) {
			out.Gated = append(out.Gated, e.path)
		}
	}
	for _, e := range exemptPaths {
		if applies(e) {
			out.Exempt = append(out.Exempt, scanevents.EgressExemption{Path: e.path, Reason: e.reason})
		}
	}
	return out
}
