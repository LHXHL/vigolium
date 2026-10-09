package network

import (
	"container/list"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-rod/rod/lib/proto"
	"go.uber.org/zap"
)

// Wire headers (Network.requestWillBeSentExtraInfo) and lazy request bodies
// (Network.getRequestPostData).
//
// requestWillBeSent carries the headers the renderer asked for. Chrome's network
// stack adds more on the way out, the Cookie header first among them, and those
// arrive only in requestWillBeSentExtraInfo. The two events are not ordered
// relative to each other: ExtraInfo can come before or after requestWillBeSent
// for the same RequestID, and a redirect chain reuses one RequestID for every
// hop. So ExtraInfo merges into the in-flight entry when it can, and is parked
// until requestWillBeSent adopts it when it cannot.
//
// requestWillBeSent also omits a large body (HasPostData with no PostData). The
// body is fetched after LoadingFinished, off the event loop, by a small worker
// pool, so a slow CDP round-trip never stalls event delivery.

const (
	// extraParkCap bounds how many RequestIDs can hold parked ExtraInfo at once.
	// The oldest is evicted past it.
	extraParkCap = 4096
	// extraParkTTL drops parked ExtraInfo no requestWillBeSent adopted in time
	// (a request served without one, or one that finished first).
	extraParkTTL = 30 * time.Second
	// extraParkPerID bounds the hops parked for one RequestID.
	extraParkPerID = 8

	// postDataWorkers is the number of goroutines fetching request bodies.
	postDataWorkers = 2
	// postDataQueue is how many fetches can wait. Past it a fetch is dropped
	// (counted) and the entry is written with the body requestWillBeSent had.
	postDataQueue = 16
	// postDataTimeout bounds one Network.getRequestPostData call.
	postDataTimeout = 5 * time.Second
	// postDataDrainTimeout bounds how long Close waits for queued writes. A
	// worker blocked on a stalled writer must not wedge Close, which is the
	// only thing that can drain that writer.
	postDataDrainTimeout = 10 * time.Second
)

// wireHeaderWinners are the headers whose ExtraInfo (on-the-wire) value replaces
// what requestWillBeSent reported. Everything else keeps the renderer's value.
var wireHeaderWinners = map[string]struct{}{
	"cookie":  {},
	"host":    {},
	"origin":  {},
	"referer": {},
}

// RequestCounters are counters a capture adds its request counts to, so a
// caller can read them while the crawl runs. Either field may be nil.
type RequestCounters struct {
	// Sent counts every http(s) request the browser issued, third-party and
	// out-of-scope included, each redirect hop separately: the network cost.
	Sent *atomic.Int64
	// InScope counts the subset the operator scope admits (all of them when
	// the capture has no ScopeFilter).
	InScope *atomic.Int64
}

// AddRequestCounters registers counters the capture increments alongside its
// own. Call before Start.
func (c *Capture) AddRequestCounters(rc RequestCounters) {
	c.mu.Lock()
	c.counterSinks = append(c.counterSinks, rc)
	c.mu.Unlock()
}

// RequestsSent reports every http(s) request the browser issued so far.
func (c *Capture) RequestsSent() int64 { return c.sent.Load() }

// RequestsSentInScope reports the in-scope share of RequestsSent.
func (c *Capture) RequestsSentInScope() int64 { return c.sentInScope.Load() }

// PostDataStats reports the lazy request-body fetches: bodies recovered, fetches
// that failed, and fetches dropped because the queue was full.
func (c *Capture) PostDataStats() (fetched, failed, dropped int64) {
	return c.postDataFetched.Load(), c.postDataFailed.Load(), c.postDataDropped.Load()
}

// countRequest records one request the browser sent and reports whether the
// operator scope admits it. Called once per requestWillBeSent, outside c.mu.
func (c *Capture) countRequest(rawURL string, u *url.URL) bool {
	inScope := true
	if c.ScopeFilter != nil && u != nil && u.Hostname() != "" {
		inScope = c.ScopeFilter(u.Hostname(), u.Path)
	}
	c.sent.Add(1)
	if inScope {
		c.sentInScope.Add(1)
	}
	c.mu.Lock()
	sinks := c.counterSinks
	c.mu.Unlock()
	for _, s := range sinks {
		if s.Sent != nil {
			s.Sent.Add(1)
		}
		if inScope && s.InScope != nil {
			s.InScope.Add(1)
		}
	}
	return inScope
}

// parkedExtra is the ExtraInfo waiting for its requestWillBeSent, per RequestID.
type parkedExtra struct {
	id      proto.NetworkRequestID
	headers []map[string]string // FIFO, one per hop
	at      time.Time
	elem    *list.Element
}

// extraPark is a bounded, TTL'd map of parked ExtraInfo. Guarded by Capture.mu.
type extraPark struct {
	byID  map[proto.NetworkRequestID]*parkedExtra
	order *list.List // oldest first
}

func (p *extraPark) init() {
	if p.byID == nil {
		p.byID = make(map[proto.NetworkRequestID]*parkedExtra)
		p.order = list.New()
	}
}

func (p *extraPark) put(id proto.NetworkRequestID, h map[string]string, now time.Time) {
	p.init()
	pe, ok := p.byID[id]
	if !ok {
		for len(p.byID) >= extraParkCap {
			p.remove(p.order.Front().Value.(*parkedExtra).id)
		}
		pe = &parkedExtra{id: id}
		pe.elem = p.order.PushBack(pe)
		p.byID[id] = pe
	} else {
		p.order.MoveToBack(pe.elem)
	}
	pe.at = now
	if len(pe.headers) >= extraParkPerID {
		pe.headers = pe.headers[1:]
	}
	pe.headers = append(pe.headers, h)
}

// take pops the first parked hop for id whose host matches rawURL.
func (p *extraPark) take(id proto.NetworkRequestID, rawURL string, now time.Time) (map[string]string, bool) {
	pe, ok := p.byID[id]
	if !ok {
		return nil, false
	}
	if now.Sub(pe.at) > extraParkTTL {
		p.remove(id)
		return nil, false
	}
	for i, h := range pe.headers {
		if wireHostMatches(rawURL, h) {
			pe.headers = append(pe.headers[:i:i], pe.headers[i+1:]...)
			if len(pe.headers) == 0 {
				p.remove(id)
			}
			return h, true
		}
	}
	return nil, false
}

func (p *extraPark) remove(id proto.NetworkRequestID) {
	if pe, ok := p.byID[id]; ok {
		p.order.Remove(pe.elem)
		delete(p.byID, id)
	}
}

// expire drops everything parked longer than extraParkTTL.
func (p *extraPark) expire(now time.Time) int {
	n := 0
	for p.order != nil {
		front := p.order.Front()
		if front == nil {
			break
		}
		pe := front.Value.(*parkedExtra)
		if now.Sub(pe.at) <= extraParkTTL {
			break
		}
		p.remove(pe.id)
		n++
	}
	return n
}

func (p *extraPark) len() int { return len(p.byID) }

// onRequestWillBeSentExtraInfo merges the wire headers into the in-flight entry
// for the RequestID, or parks them until its requestWillBeSent arrives.
//
// An entry takes at most one ExtraInfo. A second one for the same RequestID
// belongs to a later redirect hop and is parked for that hop's
// requestWillBeSent. A host that disagrees with the entry's URL means the same
// thing (a cross-host redirect whose ExtraInfo ran ahead).
func (c *Capture) onRequestWillBeSentExtraInfo(e *proto.NetworkRequestWillBeSentExtraInfo) {
	if e == nil {
		return
	}
	headers := convertHeaders(e.Headers)
	if n := blockedCookieCount(e.AssociatedCookies); n > 0 {
		zap.L().Debug("Browser withheld cookies from a request",
			zap.String("requestID", string(e.RequestID)), zap.Int("blocked", n))
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if p, ok := c.pending[e.RequestID]; ok && !p.extraSeen && wireHostMatches(p.entry.Request.URL, headers) {
		mergeWireHeaders(p.entry.Request.Headers, headers)
		p.extraSeen = true
		return
	}
	c.extraParked.put(e.RequestID, headers, time.Now())
}

// adoptParkedExtra merges parked ExtraInfo into a new pending entry. Caller
// holds c.mu.
func (c *Capture) adoptParkedExtra(id proto.NetworkRequestID, p *pendingEntry) {
	if h, ok := c.extraParked.take(id, p.entry.Request.URL, time.Now()); ok {
		mergeWireHeaders(p.entry.Request.Headers, h)
		p.extraSeen = true
	}
}

// forgetRequest drops parked ExtraInfo for a finished request. Caller holds c.mu.
func (c *Capture) forgetRequest(id proto.NetworkRequestID) {
	c.extraParked.remove(id)
}

// mergeWireHeaders applies the wire value of each wireHeaderWinners header in
// wire onto dst, replacing any case variant already there. The key keeps the
// spelling dst used, or the canonical form for a header dst did not have.
func mergeWireHeaders(dst, wire map[string]string) {
	if dst == nil {
		return
	}
	for k, v := range wire {
		lk := strings.ToLower(k)
		if _, ok := wireHeaderWinners[lk]; !ok {
			continue
		}
		key := http.CanonicalHeaderKey(lk)
		for existing := range dst {
			if strings.EqualFold(existing, k) {
				key = existing
				delete(dst, existing)
			}
		}
		dst[key] = v
	}
}

// wireHostMatches reports whether wire headers can belong to a request for
// rawURL: true unless they name a different host (Host, or :authority on
// HTTP/2). Ports are ignored, since a URL spells a default port and the Host
// header may not.
func wireHostMatches(rawURL string, wire map[string]string) bool {
	var host string
	for k, v := range wire {
		if strings.EqualFold(k, "host") || k == ":authority" {
			host = v
			break
		}
	}
	if host == "" {
		return true
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return true
	}
	return strings.EqualFold(stripPort(host), u.Hostname())
}

func stripPort(hostport string) string {
	if strings.HasPrefix(hostport, "[") {
		if i := strings.IndexByte(hostport, ']'); i > 0 {
			return hostport[1:i]
		}
	}
	if i := strings.LastIndexByte(hostport, ':'); i >= 0 && strings.Count(hostport, ":") == 1 {
		return hostport[:i]
	}
	return hostport
}

func blockedCookieCount(cookies []*proto.NetworkAssociatedCookie) int {
	n := 0
	for _, ac := range cookies {
		if ac != nil && len(ac.BlockedReasons) > 0 {
			n++
		}
	}
	return n
}

// needsPostDataFetch reports whether requestWillBeSent left the body out (or
// split it into entries) so it has to be fetched over CDP.
func needsPostDataFetch(r *proto.NetworkRequest) bool {
	return r != nil && r.HasPostData && (r.PostData == "" || len(r.PostDataEntries) > 0)
}

// postDataJob is a finished entry waiting for its request body.
type postDataJob struct {
	entry     *TrafficEntry
	sessionID proto.TargetSessionID
	requestID proto.NetworkRequestID
}

// startPostDataWorkers starts the body-fetch workers. Called from Start; a
// Capture that was never started writes entries without fetching.
func (c *Capture) startPostDataWorkers() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.postJobs != nil || c.postClosed {
		return
	}
	c.postJobs = make(chan postDataJob, postDataQueue)
	for range postDataWorkers {
		c.postWG.Add(1)
		go func(jobs <-chan postDataJob) {
			defer c.postWG.Done()
			for job := range jobs {
				c.runPostDataJob(job)
			}
		}(c.postJobs)
	}
}

// enqueuePostData hands entry to the body-fetch workers, or writes it as it is
// when they are not running or are full (the latter counted as a drop).
func (c *Capture) enqueuePostData(job postDataJob) {
	c.mu.Lock()
	if c.postJobs == nil || c.postClosed {
		c.mu.Unlock()
		c.writeEntry(job.entry)
		return
	}
	select {
	case c.postJobs <- job:
		c.mu.Unlock()
		return
	default:
	}
	c.mu.Unlock()
	c.postDataDropped.Add(1)
	zap.L().Debug("Request body fetch dropped: queue full",
		zap.String("url", job.entry.Request.URL))
	c.writeEntry(job.entry)
}

// runPostDataJob fetches the body for one entry (best-effort) and writes it.
// Queued fetches still run while Close drains, the browser being alive until
// the capture is closed, but none starts so late that it could outlast the
// drain; past that point entries are written with the body they had.
func (c *Capture) runPostDataJob(job postDataJob) {
	if d := c.drainFetchCutoff.Load(); d == 0 || time.Now().UnixNano() < d {
		body, err := c.fetchRequestPostData(job.sessionID, job.requestID)
		switch {
		case err != nil:
			c.postDataFailed.Add(1)
			// "No post data available" for an evicted request is expected.
			zap.L().Debug("Could not fetch request body",
				zap.String("url", job.entry.Request.URL), zap.Error(err))
		case len(body) == 0:
		case c.postBodyTooLarge(len(body)):
			c.postDataFailed.Add(1)
			zap.L().Debug("Request body over the capture ceiling, not kept",
				zap.String("url", job.entry.Request.URL), zap.Int("bytes", len(body)))
		case len(body) >= len(job.entry.Request.Body):
			job.entry.Request.Body = body
			c.postDataFetched.Add(1)
		}
	}
	c.writeEntry(job.entry)
}

// postBodyTooLarge applies the capture's body ceiling (SetMaxBodyBytes) to a
// fetched request body. A body over it is not stored: a truncated multipart
// body is not one that can be replayed.
func (c *Capture) postBodyTooLarge(n int) bool {
	c.mu.Lock()
	limit := c.maxBodyBytes
	c.mu.Unlock()
	if limit == 0 {
		limit = DefaultMaxDynamicBodyBytes
	}
	return limit > 0 && int64(n) > limit
}

// fetchRequestPostData calls Network.getRequestPostData on the session that
// owns the request (a page or a service worker). The test seam postDataFetcher
// replaces it.
func (c *Capture) fetchRequestPostData(sessionID proto.TargetSessionID, requestID proto.NetworkRequestID) ([]byte, error) {
	if c.postDataFetcher != nil {
		return c.postDataFetcher(sessionID, requestID)
	}
	if c.browser == nil {
		return nil, fmt.Errorf("browser not set")
	}
	ctx, cancel := context.WithTimeout(c.browser.GetContext(), postDataTimeout)
	defer cancel()
	req := proto.NetworkGetRequestPostData{RequestID: requestID}
	raw, err := c.browser.Call(ctx, string(sessionID), req.ProtoReq(), req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("timeout fetching request body after %s: %w", postDataTimeout, err)
		}
		return nil, err
	}
	return decodePostData(raw)
}

// decodePostData reads a getRequestPostData result. Newer Chrome adds
// base64Encoded for bodies that are not valid UTF-8; go-rod's result type
// predates it, so the field is read here.
func decodePostData(raw []byte) ([]byte, error) {
	var res struct {
		PostData      string `json:"postData"`
		Base64Encoded bool   `json:"base64Encoded"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, err
	}
	if res.Base64Encoded {
		return base64.StdEncoding.DecodeString(res.PostData)
	}
	return []byte(res.PostData), nil
}

// stopPostDataWorkers stops taking new fetches and waits (bounded) for the
// queued entries to be written. Safe to call more than once.
func (c *Capture) stopPostDataWorkers() {
	c.drainFetchCutoff.CompareAndSwap(0, time.Now().Add(postDataDrainTimeout-postDataTimeout).UnixNano())
	c.mu.Lock()
	if c.postJobs != nil && !c.postClosed {
		close(c.postJobs)
	}
	c.postClosed = true
	c.mu.Unlock()

	done := make(chan struct{})
	go func() {
		c.postWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(postDataDrainTimeout):
		zap.L().Warn("Request body workers did not drain in time; their entries are dropped",
			zap.Duration("waited", postDataDrainTimeout))
	}
}

// postDataState groups the worker fields embedded in Capture.
type postDataState struct {
	postJobs   chan postDataJob // guarded by Capture.mu
	postClosed bool             // guarded by Capture.mu
	postWG     sync.WaitGroup
	// drainFetchCutoff (unix nanos, 0 while running) is the last moment a
	// draining worker may start a fetch.
	drainFetchCutoff atomic.Int64

	postDataFetched atomic.Int64
	postDataFailed  atomic.Int64
	postDataDropped atomic.Int64

	// postDataFetcher replaces the CDP call in tests.
	postDataFetcher func(proto.TargetSessionID, proto.NetworkRequestID) ([]byte, error)
}
