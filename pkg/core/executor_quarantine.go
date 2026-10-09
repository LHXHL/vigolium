package core

import (
	"sort"
	"sync"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// quarantinedHostCap bounds ExecutionReport.QuarantinedHosts. The counts stay
// exact past the cap (SkippedQuarantined); only the per-host detail is clipped.
const quarantinedHostCap = 50

// QuarantinedHost is one host:port whose input items this run dropped because
// the dead-host breaker had it quarantined.
type QuarantinedHost struct {
	// Host is the breaker key, "host:port".
	Host string `json:"host"`
	// Items is how many input items were dropped for it (skipped_quarantined).
	Items int64 `json:"skipped_quarantined"`
	// State is the breaker state at report time: open, half_open, dead, or
	// closed when the host recovered after the skips.
	State string `json:"state"`
	// Class is the transport error class of the failure that quarantined it,
	// one of the http.TransportErr* constants.
	Class string `json:"class,omitempty"`
}

// quarantineSkips counts input items dropped for a quarantined host, per
// host:port. Written only when an item is dropped, never on the healthy path.
type quarantineSkips struct {
	mu     sync.Mutex
	byHost map[string]int64
	total  int64
}

func (q *quarantineSkips) add(key string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.byHost == nil {
		q.byHost = make(map[string]int64)
	}
	q.byHost[key]++
	q.total++
}

func (q *quarantineSkips) reset() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.byHost = nil
	q.total = 0
}

func (q *quarantineSkips) snapshot() (int64, map[string]int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.total == 0 {
		return 0, nil
	}
	hosts := make(map[string]int64, len(q.byHost))
	for k, v := range q.byHost {
		hosts[k] = v
	}
	return q.total, hosts
}

// hostErrors returns the scan's dead-host breaker, or nil when host error
// tracking is off.
func (e *Executor) hostErrors() *hosterrors.Cache {
	if e.cfg.Services == nil {
		return nil
	}
	return e.cfg.Services.HostErrors
}

// skipQuarantined reports whether item's host:port is quarantined, counting the
// skip when it is. It uses the breaker's read-only Quarantined, never Admit: the
// half-open probe belongs to whichever request the requester sends first, and
// a pre-filter that claimed it would leave the host with no probe at all.
func (e *Executor) skipQuarantined(req *httpmsg.HttpRequestResponse) bool {
	hc := e.hostErrors()
	if hc == nil {
		return false
	}
	key := httpmsg.HostPortKey(req)
	if key == "" || !hc.Quarantined(key) {
		return false
	}
	e.quarantine.add(key)
	return true
}

// quarantineReport fills rep's quarantine fields for this run.
func (e *Executor) quarantineReport(rep *ExecutionReport) {
	total, hosts := e.quarantine.snapshot()
	rep.SkippedQuarantined = total
	if total == 0 {
		return
	}
	hc := e.hostErrors()
	keys := make([]string, 0, len(hosts))
	for k := range hosts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > quarantinedHostCap {
		keys = keys[:quarantinedHostCap]
	}
	rep.QuarantinedHosts = make([]QuarantinedHost, 0, len(keys))
	for _, k := range keys {
		qh := QuarantinedHost{Host: k, Items: hosts[k]}
		if hc != nil {
			qh.State = hc.State(k).String()
			qh.Class = http.ClassifyTransportError(hc.LastError(k))
		}
		rep.QuarantinedHosts = append(rep.QuarantinedHosts, qh)
	}
}
