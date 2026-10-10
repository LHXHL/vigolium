package authentication

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// live.go keeps one session logged in for the length of a scan. A LiveSession
// owns the session's current credentials (lock-free for the request path),
// watches the scan's responses for the session's `check.logged_out` signs, and
// when they appear confirms with the `check.url` probe and re-runs the login
// (Manager.Rehydrate). The Requester applies Credentials() to every request,
// calls Wait before admitting one (so a re-login is not raced by requests that
// would only come back logged out) and Observe after the response.
//
// State machine, one cycle per credential generation:
//
//	valid ──logged_out match (gen current)──▶ suspect ──probe says logged in──▶ valid
//	                                             │
//	                                             └──probe says logged out──▶ refreshing ──login ok──▶ valid (gen+1)
//	                                                                             │
//	                                                                             └──max_attempts failed──▶ failed
//
// Exactly one goroutine — the one whose CAS moved valid→suspect — confirms and
// refreshes for a generation, so 50 workers seeing the same 401 cause one probe
// and one login. A response sent with an older generation's credentials was in
// flight before the last refresh and is never evidence against the new ones.
//
// Under reauth.pause_traffic a reactive cycle (scan traffic or the interval
// probe looked logged out) holds new requests in Wait from the moment it
// leaves valid — through the confirm probe as well as the login — until it
// ends. The responses that come back logged out are then only those already
// past Wait when the cycle began: bounded by the scan's concurrency, not by
// how long the probe and the login take.

// LiveState is where a LiveSession is in its cycle.
type LiveState int32

const (
	// LiveValid: the credentials are believed good.
	LiveValid LiveState = iota
	// LiveSuspect: scan traffic looked logged out; the confirm probe is running.
	LiveSuspect
	// LiveRefreshing: confirmed logged out; the login flow is re-running.
	LiveRefreshing
	// LiveFailed: re-login gave up (or is disabled). Terminal for the scan.
	LiveFailed
)

func (s LiveState) String() string {
	switch s {
	case LiveValid:
		return "valid"
	case LiveSuspect:
		return "suspect"
	case LiveRefreshing:
		return "refreshing"
	case LiveFailed:
		return "failed"
	}
	return fmt.Sprintf("LiveState(%d)", int32(s))
}

// Credentials are one generation of a session's credentials. A published
// value is never mutated: a re-login publishes a new one.
type Credentials struct {
	// Headers are the headers a request sends for the session: the session's
	// own, minus any the operator pinned with an explicit -H.
	Headers map[string]string
	// Gen numbers the generation, from 1. Each successful re-login adds one.
	Gen uint64
	// At is when this generation was minted.
	At time.Time
	// ExpiresAt is when this generation expires, when the login said so (an
	// OAuth2 token's expires_in); zero when unknown. The session refreshes
	// shortly before it (see expiryLead).
	ExpiresAt time.Time

	// all is every header the login produced, pinned or not: the confirm
	// probe sends the session's credentials, not the scan's mix.
	all map[string]string
}

// LiveEventKind names what a LiveEvent reports.
type LiveEventKind string

const (
	// LiveEventSuspect: scan traffic (or the proactive probe) looked logged out.
	LiveEventSuspect LiveEventKind = "suspect"
	// LiveEventRelogin: a re-login cycle ended; OK says how.
	LiveEventRelogin LiveEventKind = "relogin"
	// LiveEventLost: the session is logged out for good (re-login failed or is
	// disabled). The scan continues unauthenticated or aborts per on_failure.
	LiveEventLost LiveEventKind = "lost"
)

// LiveEvent is what a LiveSession tells its owner. Delivered synchronously from
// the confirm/refresh goroutine, never from the request path.
type LiveEvent struct {
	Kind    LiveEventKind
	Session string
	// Gen is the generation the event is about: the suspected one for suspect
	// and a failed relogin, the NEW one for a successful relogin.
	Gen uint64
	OK  bool
	// Reason says what triggered a suspect: "status", "redirect", "body"
	// (a logged_out match), "interval" (the proactive probe), "expiry" (the
	// credentials are about to expire) or "invalidate".
	Reason string
	// Attempts is how many logins a relogin cycle ran.
	Attempts  int
	Err       error
	OnFailure ReauthOnFailure
}

// LiveOptions configures a LiveSession.
type LiveOptions struct {
	// Manager re-runs the login (Rehydrate) and supplies the probe transport.
	// Nil disables re-login: a confirmed logout goes straight to failed.
	Manager *Manager
	// ProbeClient sends the check.url probe. Nil uses the manager's login
	// transport with redirects not followed (Go's default transport when
	// there is no manager).
	ProbeClient *http.Client
	// ProbeBase resolves a relative check.url (a scan target). Empty falls back
	// to the login URL.
	ProbeBase string
	// Pinned are header names the operator set explicitly (-H): the session
	// never overrides them.
	Pinned []string
	// OnEvent receives suspect / relogin / lost events. Optional.
	OnEvent func(LiveEvent)
	// Context bounds the probes and re-logins; Close cancels it too.
	Context context.Context
	// WaitBudget bounds how long Wait parks a request during a re-login.
	// Zero uses the manager's login budget (DefaultLoginBudget).
	WaitBudget time.Duration

	// Test seams. Nil means the real clock.
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
}

// Detection without an active probe: K logged_out matches inside window make
// the logout confirmed (a single 401 from a module's payload must not cost a
// re-login).
const (
	liveSuspectK      = 3
	liveSuspectWindow = 10 * time.Second
	// liveConfirmCooldown: after the probe found the session logged in, more
	// logged_out matches in this window are not re-probed. A module that keeps
	// provoking 401s on a valid session would otherwise probe back to back.
	liveConfirmCooldown = 2 * time.Second
	// liveBodyCap is the most of a response body the sampled regex reads.
	liveBodyCap = 64 << 10
	// Credentials with a known expiry are refreshed a lead time before it:
	// a tenth of their lifetime, clamped to [liveExpiryLeadMin,
	// liveExpiryLeadMax], and never more than half the lifetime.
	liveExpiryLeadMin = 5 * time.Second
	liveExpiryLeadMax = 60 * time.Second
)

// expiryLead is how long before expiresAt credentials minted at mintedAt are
// refreshed.
func expiryLead(mintedAt, expiresAt time.Time) time.Duration {
	life := expiresAt.Sub(mintedAt)
	lead := life / 10
	if lead < liveExpiryLeadMin {
		lead = liveExpiryLeadMin
	}
	if lead > liveExpiryLeadMax {
		lead = liveExpiryLeadMax
	}
	if half := life / 2; lead > half {
		lead = half
	}
	if lead < 0 {
		lead = 0
	}
	return lead
}

// LiveSession is the scan-time owner of one session's credentials. All
// methods are safe for concurrent use; a nil *LiveSession is inert.
type LiveSession struct {
	name      string
	matcher   *CheckMatcher
	probeURL  string
	method    string
	pinned    map[string]struct{}
	manager   *Manager
	probeCl   *http.Client
	onEvent   func(LiveEvent)
	now       func() time.Time
	sleep     func(ctx context.Context, d time.Duration) error
	ctx       context.Context
	cancel    context.CancelFunc
	waitLimit time.Duration

	sampleEvery uint64
	interval    time.Duration
	reauth      bool
	maxAttempts int
	backoff     time.Duration
	pause       bool
	onFailure   ReauthOnFailure

	creds atomic.Pointer[Credentials]
	state atomic.Int32
	// hold, when set, parks Wait callers until it is closed: the cycle that
	// raised it (begin) closes it when it ends. Nil while traffic flows.
	hold atomic.Pointer[chan struct{}]
	// cycleMu makes each valid→suspect move (begin) one step with raising
	// the hold, so no request is admitted in between. Never taken on the
	// request path: only on a logged_out match and by the timers.
	cycleMu sync.Mutex

	sampled   atomic.Uint64
	observed  atomic.Int64
	loggedOut atomic.Int64
	// confirmedAt is when the probe last found the session logged in (unix ns).
	confirmedAt atomic.Int64

	// mu serializes refresh; never taken on the request path.
	mu    sync.Mutex
	fails int

	// hits are the recent logged_out matches for hitGen (K-of-N rule, used
	// when there is no probe). Only matched responses take hitMu.
	hitMu  sync.Mutex
	hitGen uint64
	hits   []time.Time

	timerMu sync.Mutex
	timer   *time.Timer
	// expTimer fires the refresh ahead of the current credentials' expiry.
	expTimer *time.Timer
	closed   bool
	wg       sync.WaitGroup
}

// NewLiveSession builds the live owner of sess, which must be hydrated and
// carry a check block (call Session.ApplyDefaults first) or credentials with
// a known expiry (an OAuth2 login). It starts the proactive probe timer when
// check.interval is set and the expiry timer when the credentials expire;
// Close stops both.
func NewLiveSession(sess *Session, opt LiveOptions) (*LiveSession, error) {
	if sess == nil || (sess.Check == nil && sess.expiresAt.IsZero()) {
		return nil, errors.New("live session: no check block and no credential expiry")
	}
	check := sess.Check
	if check == nil {
		check = &SessionCheck{}
	}
	m, err := check.Compile()
	if err != nil {
		return nil, fmt.Errorf("session %q: %w", sess.Name, err)
	}
	s := &LiveSession{
		name:        sess.Name,
		matcher:     m,
		method:      check.EffectiveMethod(),
		pinned:      make(map[string]struct{}, len(opt.Pinned)),
		manager:     opt.Manager,
		probeCl:     opt.ProbeClient,
		onEvent:     opt.OnEvent,
		now:         opt.Now,
		sleep:       opt.Sleep,
		waitLimit:   opt.WaitBudget,
		sampleEvery: uint64(check.EffectiveSampleEvery()),
		interval:    check.Interval.D(),
		reauth:      sess.ReauthEnabled() && opt.Manager != nil,
		maxAttempts: sess.Reauth.EffectiveMaxAttempts(),
		backoff:     sess.Reauth.EffectiveBackoff(),
		pause:       sess.Reauth.EffectivePauseTraffic(),
		onFailure:   sess.Reauth.EffectiveOnFailure(),
	}
	for _, name := range opt.Pinned {
		s.pinned[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.sleep == nil {
		s.sleep = sleepCtx
	}
	if s.waitLimit <= 0 {
		s.waitLimit = opt.Manager.LoginBudget()
	}
	if strings.TrimSpace(check.URL) != "" {
		base := opt.ProbeBase
		if base == "" && sess.Login != nil {
			base = sess.Login.LoginURL()
		}
		u, err := ResolveCheckURL(check.URL, base)
		if err != nil {
			return nil, fmt.Errorf("session %q: check.url: %w", sess.Name, err)
		}
		s.probeURL = u
	}
	if s.probeCl == nil {
		if opt.Manager != nil {
			s.probeCl = opt.Manager.probeClient()
		} else {
			s.probeCl = &http.Client{
				Timeout:       loginRequestTimeout,
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			}
		}
	}
	parent := opt.Context
	if parent == nil {
		parent = context.Background()
	}
	s.ctx, s.cancel = context.WithCancel(parent)

	first := s.mint(sess.Headers, 1, sess.expiresAt)
	s.creds.Store(first)
	s.state.Store(int32(LiveValid))

	if s.interval > 0 && s.probeURL != "" {
		s.timer = time.AfterFunc(s.interval, s.tick)
	}
	s.armExpiry(first)
	return s, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// mint builds generation gen from the headers a login produced, which
// expire at expiresAt (zero: unknown).
func (s *LiveSession) mint(headers map[string]string, gen uint64, expiresAt time.Time) *Credentials {
	c := &Credentials{
		Headers:   make(map[string]string, len(headers)),
		all:       make(map[string]string, len(headers)),
		Gen:       gen,
		At:        s.now(),
		ExpiresAt: expiresAt,
	}
	for k, v := range headers {
		c.all[k] = v
		if _, pinned := s.pinned[strings.ToLower(k)]; !pinned {
			c.Headers[k] = v
		}
	}
	return c
}

// Name is the session's name.
func (s *LiveSession) Name() string {
	if s == nil {
		return ""
	}
	return s.name
}

// Credentials is the current generation. Lock-free; never nil on a live
// session (nil on a nil receiver).
func (s *LiveSession) Credentials() *Credentials {
	if s == nil {
		return nil
	}
	return s.creds.Load()
}

// State is where the session is in its cycle.
func (s *LiveSession) State() LiveState {
	if s == nil {
		return LiveValid
	}
	return LiveState(s.state.Load())
}

// OnFailure is the session's reauth.on_failure policy.
func (s *LiveSession) OnFailure() ReauthOnFailure {
	if s == nil {
		return ReauthContinue
	}
	return s.onFailure
}

// Observed counts the responses Observe was given.
func (s *LiveSession) Observed() int64 {
	if s == nil {
		return 0
	}
	return s.observed.Load()
}

// LoggedOutResponses counts responses the scan received while the session was
// logged out: every logged_out match (from any generation), plus every
// response once the session has failed. Work behind them ran unauthenticated;
// v1 reports the count rather than re-queueing it.
func (s *LiveSession) LoggedOutResponses() int64 {
	if s == nil {
		return 0
	}
	return s.loggedOut.Load()
}

// Observe feeds one scan response, sent with generation gen's credentials, to
// the logged-out detector. It never blocks: status and Location are checked
// on every response, the logged_out body regex on one in check.sample_every
// (first 64 KiB), and a match that needs confirming hands off to a goroutine.
func (s *LiveSession) Observe(gen uint64, status int, header http.Header, body []byte) {
	if s == nil {
		return
	}
	s.observed.Add(1)
	st := LiveState(s.state.Load())
	if st == LiveFailed {
		s.loggedOut.Add(1)
		return
	}
	if !s.matcher.HasLoggedOut() {
		return
	}
	checkBody := s.sampled.Add(1)%s.sampleEvery == 0
	p := ProbeResponse{Status: status, Header: header}
	if checkBody {
		if len(body) > liveBodyCap {
			body = body[:liveBodyCap]
		}
		p.Body = body
	}
	out, how := s.matcher.LoggedOut(&p, checkBody)
	if !out {
		return
	}
	s.loggedOut.Add(1)
	if st != LiveValid || gen != s.creds.Load().Gen {
		// Already being handled, or a response to credentials that have
		// since been replaced.
		return
	}
	if s.recentlyConfirmed() {
		return
	}
	if s.probeURL == "" && !s.kOfN(gen) {
		return
	}
	s.trigger(gen, how, false)
}

// Invalidate reports generation gen as logged out, skipping the confirm
// probe. Only the first caller for the current generation starts a re-login;
// it returns whether this call did.
func (s *LiveSession) Invalidate(gen uint64) bool {
	if s == nil {
		return false
	}
	return s.trigger(gen, "invalidate", true)
}

// Wait parks the caller while the session confirms a suspected logout and
// re-logs in, when reauth pause_traffic is on (the default), so requests are
// not sent with credentials about to be replaced. An expiry refresh does not
// park (the credentials are still good while it runs). It returns at once when
// nothing is held, when the cycle ends, after the login budget, or with ctx's
// error when ctx ends first. Call it BEFORE taking an egress host slot: a
// parked request must not hold a slot the re-login needs.
func (s *LiveSession) Wait(ctx context.Context) error {
	if s == nil || !s.pause {
		return nil
	}
	chp := s.hold.Load()
	if chp == nil {
		return nil
	}
	t := time.NewTimer(s.waitLimit)
	defer t.Stop()
	select {
	case <-*chp:
		return nil
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close stops the proactive probe, cancels any probe or login in flight and
// waits for them to return. Idempotent.
func (s *LiveSession) Close() {
	if s == nil {
		return
	}
	s.timerMu.Lock()
	s.closed = true
	if s.timer != nil {
		s.timer.Stop()
	}
	if s.expTimer != nil {
		s.expTimer.Stop()
	}
	s.timerMu.Unlock()
	s.cancel()
	s.wg.Wait()
}

func (s *LiveSession) recentlyConfirmed() bool {
	at := s.confirmedAt.Load()
	return at != 0 && s.now().Sub(time.Unix(0, at)) < liveConfirmCooldown
}

// kOfN records a logged_out match for gen and reports whether K of them fell
// inside the window.
func (s *LiveSession) kOfN(gen uint64) bool {
	now := s.now()
	s.hitMu.Lock()
	defer s.hitMu.Unlock()
	if s.hitGen != gen {
		s.hitGen, s.hits = gen, s.hits[:0]
	}
	keep := s.hits[:0]
	for _, t := range s.hits {
		if now.Sub(t) < liveSuspectWindow {
			keep = append(keep, t)
		}
	}
	s.hits = append(keep, now)
	return len(s.hits) >= liveSuspectK
}

// begin moves valid→suspect for gen and reports whether this call did; the
// caller then owns the cycle and calls release when it ends. With hold (and
// pause_traffic on) Wait parks new requests from before the state changes
// until release. It fails when another cycle owns the session, or when a
// refresh has already published a newer generation (the evidence is stale).
func (s *LiveSession) begin(gen uint64, hold bool) (release func(), ok bool) {
	s.cycleMu.Lock()
	defer s.cycleMu.Unlock()
	if LiveState(s.state.Load()) != LiveValid || s.creds.Load().Gen != gen {
		return nil, false
	}
	release = func() {}
	if hold && s.pause {
		ch := make(chan struct{})
		s.hold.Store(&ch)
		release = func() {
			s.hold.CompareAndSwap(&ch, nil)
			close(ch)
		}
	}
	// Every valid→suspect move happens here under cycleMu, and only the
	// cycle's owner leaves suspect, so a plain store cannot lose a race.
	s.state.Store(int32(LiveSuspect))
	return release, true
}

// trigger moves valid→suspect for gen; the winner confirms and refreshes on
// its own goroutine. Returns whether this call won.
func (s *LiveSession) trigger(gen uint64, reason string, confirmed bool) bool {
	release, ok := s.begin(gen, true)
	if !ok {
		return false
	}
	if !s.track() {
		s.state.CompareAndSwap(int32(LiveSuspect), int32(LiveValid))
		release()
		return false
	}
	go func() {
		defer s.wg.Done()
		defer release()
		s.confirmAndRefresh(gen, reason, confirmed)
	}()
	return true
}

// track adds one to wg unless the session is closed.
func (s *LiveSession) track() bool {
	s.timerMu.Lock()
	defer s.timerMu.Unlock()
	if s.closed {
		return false
	}
	s.wg.Add(1)
	return true
}

func (s *LiveSession) confirmAndRefresh(gen uint64, reason string, confirmed bool) {
	s.emit(LiveEvent{Kind: LiveEventSuspect, Gen: gen, Reason: reason})
	if !confirmed && s.probeURL != "" {
		in, err := s.probe(s.ctx)
		if err != nil || in {
			// Logged in after all (a module provoked the 401), or the probe
			// could not tell: keep the credentials.
			if err != nil {
				zap.L().Debug("Session check probe failed; keeping credentials",
					zap.String("session", s.name), zap.Error(err))
			}
			s.confirmedAt.Store(s.now().UnixNano())
			s.state.CompareAndSwap(int32(LiveSuspect), int32(LiveValid))
			return
		}
	}
	s.refresh(gen)
}

// refresh re-runs the login for gen (state is suspect, owned by the caller).
// The caller releases its traffic hold after refresh returns, so parked
// requests resume only once the outcome — an on_failure: abort included —
// has been reported.
func (s *LiveSession) refresh(gen uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.creds.Load().Gen != gen {
		s.state.CompareAndSwap(int32(LiveSuspect), int32(LiveValid))
		return
	}
	if !s.reauth {
		s.state.Store(int32(LiveFailed))
		s.emit(LiveEvent{Kind: LiveEventLost, Gen: gen, OnFailure: s.onFailure,
			Err: errors.New("session is logged out and re-login is disabled (no login flow, or reauth.enabled: false)")})
		return
	}

	s.state.Store(int32(LiveRefreshing))

	var lastErr error
	attempts := 0
	for attempt := 1; attempt <= s.maxAttempts; attempt++ {
		attempts = attempt
		headers, expiresAt, err := s.manager.rehydrate(s.ctx, s.name)
		if err == nil {
			next := s.mint(headers, gen+1, expiresAt)
			s.creds.Store(next)
			s.fails = 0
			s.confirmedAt.Store(0)
			s.state.Store(int32(LiveValid))
			s.emit(LiveEvent{Kind: LiveEventRelogin, Gen: next.Gen, OK: true, Attempts: attempts})
			s.armExpiry(next)
			return
		}
		lastErr = err
		s.fails++
		zap.L().Warn("Session re-login failed",
			zap.String("session", s.name), zap.Int("attempt", attempt),
			zap.Int("max_attempts", s.maxAttempts), zap.Error(err))
		if attempt == s.maxAttempts || s.ctx.Err() != nil {
			break
		}
		if err := s.sleep(s.ctx, s.backoff<<(attempt-1)); err != nil {
			break
		}
	}
	s.state.Store(int32(LiveFailed))
	s.emit(LiveEvent{Kind: LiveEventRelogin, Gen: gen, OK: false, Attempts: attempts, Err: lastErr})
	s.emit(LiveEvent{Kind: LiveEventLost, Gen: gen, Attempts: attempts, Err: lastErr, OnFailure: s.onFailure})
}

// probe sends the check.url request with the current credentials and reports
// whether the session is logged in: check.logged_in when configured, else
// "not refused" (no logged_out match, no 401/403, no login redirect or form).
func (s *LiveSession) probe(ctx context.Context) (bool, error) {
	if s.probeURL == "" {
		return false, errors.New("no check.url")
	}
	creds := s.creds.Load()
	req, err := http.NewRequestWithContext(ctx, s.method, s.probeURL, nil)
	if err != nil {
		return false, err
	}
	for k, v := range creds.all {
		req.Header.Set(k, v)
	}
	resp, err := s.probeCl.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, liveBodyCap))
	if err != nil {
		return false, err
	}
	p := &ProbeResponse{Status: resp.StatusCode, Header: resp.Header, Body: body, URL: s.probeURL}
	if s.matcher.HasLoggedIn() {
		in, _ := s.matcher.LoggedIn(p)
		return in, nil
	}
	if out, _ := s.matcher.LoggedOut(p, true); out {
		return false, nil
	}
	return !isDenied(p.Status) && loginSignal(p) == "", nil
}

// tick is the proactive interval probe.
func (s *LiveSession) tick() {
	if !s.track() {
		return
	}
	defer s.wg.Done()
	defer s.rearm()
	if LiveState(s.state.Load()) != LiveValid {
		return
	}
	gen := s.creds.Load().Gen
	in, err := s.probe(s.ctx)
	if err != nil || in {
		return
	}
	release, ok := s.begin(gen, true)
	if !ok {
		return
	}
	defer release()
	s.emit(LiveEvent{Kind: LiveEventSuspect, Gen: gen, Reason: "interval"})
	s.refresh(gen)
}

// armExpiry schedules the refresh of c a lead time before it expires. A
// session that cannot re-login (no login flow, reauth disabled) is left to
// the logged-out detection.
func (s *LiveSession) armExpiry(c *Credentials) {
	if c == nil || c.ExpiresAt.IsZero() || !s.reauth {
		return
	}
	delay := c.ExpiresAt.Sub(s.now()) - expiryLead(c.At, c.ExpiresAt)
	if delay < 0 {
		delay = 0
	}
	gen := c.Gen
	s.timerMu.Lock()
	defer s.timerMu.Unlock()
	if s.closed {
		return
	}
	if s.expTimer != nil {
		s.expTimer.Stop()
	}
	s.expTimer = time.AfterFunc(delay, func() { s.expire(gen) })
}

// expire refreshes generation gen ahead of its expiry, without a confirm
// probe (the token is known to be about to lapse) and without parking
// traffic (it is still valid while the refresh runs).
func (s *LiveSession) expire(gen uint64) {
	if !s.track() {
		return
	}
	defer s.wg.Done()
	// No hold: the credentials stay valid while the refresh runs.
	release, ok := s.begin(gen, false)
	if !ok {
		return // a reactive refresh is already running, or gen is stale
	}
	defer release()
	s.emit(LiveEvent{Kind: LiveEventSuspect, Gen: gen, Reason: "expiry"})
	s.refresh(gen)
}

func (s *LiveSession) rearm() {
	s.timerMu.Lock()
	defer s.timerMu.Unlock()
	if !s.closed && s.timer != nil && LiveState(s.state.Load()) != LiveFailed {
		s.timer.Reset(s.interval)
	}
}

func (s *LiveSession) emit(ev LiveEvent) {
	ev.Session = s.name
	switch ev.Kind {
	case LiveEventSuspect:
		zap.L().Info("Session looks logged out; confirming",
			zap.String("session", s.name), zap.Uint64("gen", ev.Gen), zap.String("reason", ev.Reason))
	case LiveEventRelogin:
		if ev.OK {
			zap.L().Info("Session re-login succeeded",
				zap.String("session", s.name), zap.Uint64("gen", ev.Gen), zap.Int("attempts", ev.Attempts))
		}
	case LiveEventLost:
		zap.L().Warn("Session lost: re-login did not restore it",
			zap.String("session", s.name), zap.String("on_failure", string(ev.OnFailure)), zap.Error(ev.Err))
	}
	if s.onEvent != nil {
		s.onEvent(ev)
	}
}
