package authentication

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeApp is a login server: POST /login mints sid=<n>; GET /me answers 200
// for the current sid and 401 otherwise. expire() invalidates the current sid.
type fakeApp struct {
	srv        *httptest.Server
	logins     atomic.Int64
	current    atomic.Int64 // the sid /me accepts; 0 = none
	failLogin  atomic.Bool
	probeLogIn atomic.Bool // /me answers 200 whatever the cookie
	gate       atomic.Pointer[chan struct{}]
	probeGate  atomic.Pointer[chan struct{}] // holds the /me probe until closed
}

func newFakeApp(t *testing.T) *fakeApp {
	t.Helper()
	a := &fakeApp{}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			if g := a.gate.Load(); g != nil {
				<-*g
			}
			if a.failLogin.Load() {
				http.Error(w, "nope", http.StatusInternalServerError)
				return
			}
			n := a.logins.Add(1)
			a.current.Store(n)
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: fmt.Sprint(n), Path: "/"})
			_, _ = w.Write([]byte("ok"))
		case "/me":
			if g := a.probeGate.Load(); g != nil {
				<-*g
			}
			if a.probeLogIn.Load() || r.Header.Get("Cookie") == fmt.Sprintf("sid=%d", a.current.Load()) {
				_, _ = w.Write([]byte(`{"email":"a@b.c"}`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *fakeApp) expire() { a.current.Store(-1) }

func (a *fakeApp) session(check *SessionCheck, reauth *SessionReauth) *Session {
	return &Session{
		Name:   "admin",
		Role:   RolePrimary,
		Login:  &LoginFlow{URL: a.srv.URL + "/login", Method: "POST", Type: LoginTypeCookie},
		Check:  check,
		Reauth: reauth,
	}
}

func defaultCheck() *SessionCheck {
	return &SessionCheck{
		URL:       "/me",
		LoggedIn:  &LoggedInRule{Status: []int{200}},
		LoggedOut: &LoggedOutRule{Status: []int{401}},
	}
}

type eventLog struct {
	mu  sync.Mutex
	evs []LiveEvent
}

func (l *eventLog) add(ev LiveEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evs = append(l.evs, ev)
}

func (l *eventLog) kinds() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, e := range l.evs {
		k := string(e.Kind)
		if e.Kind == LiveEventRelogin {
			k += fmt.Sprintf(":%v", e.OK)
		}
		out = append(out, k)
	}
	return out
}

// newLive hydrates sess through a manager and wraps it in a LiveSession.
func newLive(t *testing.T, sess *Session, opt LiveOptions) (*LiveSession, *Manager, *eventLog) {
	t.Helper()
	m, err := NewManager([]*Session{sess})
	require.NoError(t, err)
	require.NoError(t, m.HydrateSessions())
	log := &eventLog{}
	opt.Manager = m
	if opt.OnEvent == nil {
		opt.OnEvent = log.add
	}
	if opt.Sleep == nil {
		opt.Sleep = func(ctx context.Context, d time.Duration) error { return ctx.Err() }
	}
	ls, err := NewLiveSession(sess, opt)
	require.NoError(t, err)
	t.Cleanup(ls.Close)
	return ls, m, log
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// 50 workers see the same 401 at the same generation: one probe, one login.
func TestLiveSession_StampedeLogsInOnce(t *testing.T) {
	app := newFakeApp(t)
	ls, _, log := newLive(t, app.session(defaultCheck(), nil), LiveOptions{})
	require.Equal(t, int64(1), app.logins.Load())
	gen := ls.Credentials().Gen
	app.expire()

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ls.Observe(gen, http.StatusUnauthorized, http.Header{}, nil)
			_ = ls.Wait(context.Background())
		}()
	}
	close(start)
	wg.Wait()
	waitUntil(t, "relogin", func() bool { return ls.Credentials().Gen == gen+1 && ls.State() == LiveValid })

	assert.Equal(t, int64(2), app.logins.Load(), "exactly one re-login")
	assert.Equal(t, "sid=2", ls.Credentials().Headers["Cookie"])
	assert.Equal(t, []string{"suspect", "relogin:true"}, log.kinds())
	assert.Equal(t, int64(50), ls.LoggedOutResponses())
}

// A 401 sent with the previous generation's credentials was in flight before
// the refresh; it must not refresh again.
func TestLiveSession_StaleGenerationIgnored(t *testing.T) {
	app := newFakeApp(t)
	ls, _, _ := newLive(t, app.session(defaultCheck(), nil), LiveOptions{})
	app.expire()
	require.True(t, ls.Invalidate(1))
	waitUntil(t, "relogin", func() bool { return ls.Credentials().Gen == 2 && ls.State() == LiveValid })
	logins := app.logins.Load()

	ls.Observe(1, http.StatusUnauthorized, http.Header{}, nil)
	assert.False(t, ls.Invalidate(1), "a stale generation cannot start a refresh")
	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, logins, app.logins.Load())
	assert.Equal(t, LiveValid, ls.State())
	assert.Equal(t, uint64(2), ls.Credentials().Gen)
}

// The probe still says logged in (the 401 came from a module's own request):
// no login, back to valid.
func TestLiveSession_ConfirmProbeAvoidsFalseRefresh(t *testing.T) {
	app := newFakeApp(t)
	ls, _, log := newLive(t, app.session(defaultCheck(), nil), LiveOptions{})
	ls.Observe(1, http.StatusUnauthorized, http.Header{}, nil)
	waitUntil(t, "confirm", func() bool { return len(log.kinds()) == 1 && ls.State() == LiveValid })
	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, int64(1), app.logins.Load(), "no re-login")
	assert.Equal(t, uint64(1), ls.Credentials().Gen)
	assert.Equal(t, []string{"suspect"}, log.kinds())
}

// Login keeps failing: backoff doubles between attempts, then failed, the
// ready channel closes and parked waiters are released.
func TestLiveSession_FailureBackoffThenFailed(t *testing.T) {
	app := newFakeApp(t)
	var mu sync.Mutex
	var slept []time.Duration
	gate := make(chan struct{})
	sleep := func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		slept = append(slept, d)
		mu.Unlock()
		<-gate // hold the cycle in refreshing until the waiter is parked
		return nil
	}
	reauth := &SessionReauth{MaxAttempts: 3, Backoff: Duration(time.Second)}
	ls, _, log := newLive(t, app.session(defaultCheck(), reauth), LiveOptions{Sleep: sleep})
	app.expire()
	app.failLogin.Store(true)

	require.True(t, ls.Invalidate(1))
	waitUntil(t, "refreshing", func() bool { return ls.State() == LiveRefreshing })
	released := make(chan error, 1)
	go func() { released <- ls.Wait(context.Background()) }()
	close(gate)

	select {
	case err := <-released:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("waiter not released after the session failed")
	}
	waitUntil(t, "failed", func() bool { return ls.State() == LiveFailed })
	mu.Lock()
	assert.Equal(t, []time.Duration{time.Second, 2 * time.Second}, slept)
	mu.Unlock()
	assert.Equal(t, []string{"suspect", "relogin:false", "lost"}, log.kinds())
	assert.Equal(t, ReauthContinue, ls.OnFailure())

	// Failed is terminal: every later response counts as logged out, and
	// nothing tries to log in again.
	before := ls.LoggedOutResponses()
	ls.Observe(1, http.StatusOK, http.Header{}, nil)
	assert.Equal(t, before+1, ls.LoggedOutResponses())
	assert.NoError(t, ls.Wait(context.Background()))
}

// Under pause_traffic a request parked in Wait leaves with the NEW credentials.
func TestLiveSession_PauseTrafficWaiterGetsNewHeader(t *testing.T) {
	app := newFakeApp(t)
	ls, _, _ := newLive(t, app.session(defaultCheck(), nil), LiveOptions{})
	app.expire()
	gate := make(chan struct{}) // the re-login blocks until released
	app.gate.Store(&gate)
	require.True(t, ls.Invalidate(1))
	waitUntil(t, "refreshing", func() bool { return ls.State() == LiveRefreshing })

	got := make(chan string, 1)
	go func() {
		_ = ls.Wait(context.Background())
		got <- ls.Credentials().Headers["Cookie"]
	}()
	select {
	case <-got:
		t.Fatal("Wait returned while the re-login was still running")
	case <-time.After(30 * time.Millisecond):
	}
	close(gate)
	select {
	case cookie := <-got:
		assert.Equal(t, "sid=2", cookie)
	case <-time.After(5 * time.Second):
		t.Fatal("waiter not released")
	}
}

// pause_traffic holds requests from the first logged_out match, not only once
// the login starts: while the confirm probe runs, Wait parks. Otherwise a slow
// probe lets the scan keep sending with credentials already known to be dead.
func TestLiveSession_PauseTrafficHoldsDuringConfirmProbe(t *testing.T) {
	for _, tc := range []struct {
		name      string
		loggedOut bool // what the probe finds
		cookie    string
	}{
		{name: "probe confirms logout", loggedOut: true, cookie: "sid=2"},
		{name: "probe finds session valid", loggedOut: false, cookie: "sid=1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := newFakeApp(t)
			ls, _, log := newLive(t, app.session(defaultCheck(), nil), LiveOptions{})
			if tc.loggedOut {
				app.expire()
			}
			probe := make(chan struct{})
			var releaseProbe sync.Once
			openProbe := func() { releaseProbe.Do(func() { close(probe) }) }
			// Registered after newFakeApp's server cleanup, so it runs first:
			// a failed assertion must not leave the server's Close waiting on
			// the held probe handler.
			t.Cleanup(openProbe)
			app.probeGate.Store(&probe)
			ls.Observe(1, http.StatusUnauthorized, http.Header{}, nil)
			require.Equal(t, LiveSuspect, ls.State(), "the match moves valid→suspect synchronously")

			got := make(chan string, 1)
			go func() {
				_ = ls.Wait(context.Background())
				got <- ls.Credentials().Headers["Cookie"]
			}()
			select {
			case <-got:
				t.Fatal("Wait returned while the confirm probe was still running")
			case <-time.After(30 * time.Millisecond):
			}
			openProbe()
			select {
			case cookie := <-got:
				assert.Equal(t, tc.cookie, cookie)
			case <-time.After(5 * time.Second):
				t.Fatal("waiter not released")
			}
			assert.Equal(t, LiveValid, ls.State())
			if tc.loggedOut {
				assert.Equal(t, []string{"suspect", "relogin:true"}, log.kinds(),
					"the waiter resumes only after the relogin was reported")
			}
			assert.NoError(t, ls.Wait(context.Background()), "nothing is held once the cycle ends")
		})
	}
}

func TestLiveSession_WaitHonoursContext(t *testing.T) {
	app := newFakeApp(t)
	ls, _, _ := newLive(t, app.session(defaultCheck(), nil), LiveOptions{})
	gate := make(chan struct{})
	app.gate.Store(&gate)
	defer close(gate)
	require.True(t, ls.Invalidate(1))
	waitUntil(t, "refreshing", func() bool { return ls.State() == LiveRefreshing })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ls.Wait(ctx) }()
	cancel()
	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled waiter not released")
	}
}

func TestLiveSession_WaitWithoutPauseNeverBlocks(t *testing.T) {
	app := newFakeApp(t)
	off := false
	ls, _, _ := newLive(t, app.session(defaultCheck(), &SessionReauth{PauseTraffic: &off}), LiveOptions{})
	gate := make(chan struct{})
	app.gate.Store(&gate)
	defer close(gate)
	require.True(t, ls.Invalidate(1))
	waitUntil(t, "refreshing", func() bool { return ls.State() == LiveRefreshing })
	assert.NoError(t, ls.Wait(context.Background()))
}

// Without check.url there is no probe, so one 401 is not enough: K matches
// inside the window confirm the logout.
func TestLiveSession_NoProbeNeedsKMatches(t *testing.T) {
	app := newFakeApp(t)
	now := time.Unix(1_700_000_000, 0)
	var clock sync.Mutex
	nowFn := func() time.Time { clock.Lock(); defer clock.Unlock(); return now }
	advance := func(d time.Duration) { clock.Lock(); now = now.Add(d); clock.Unlock() }
	check := &SessionCheck{LoggedOut: &LoggedOutRule{Status: []int{401}}}
	ls, _, _ := newLive(t, app.session(check, nil), LiveOptions{Now: nowFn})

	ls.Observe(1, 401, http.Header{}, nil)
	ls.Observe(1, 401, http.Header{}, nil)
	advance(11 * time.Second) // both fall out of the window
	ls.Observe(1, 401, http.Header{}, nil)
	ls.Observe(1, 401, http.Header{}, nil)
	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, int64(1), app.logins.Load(), "two matches in the window are not a logout")

	ls.Observe(1, 401, http.Header{}, nil)
	waitUntil(t, "relogin", func() bool { return ls.Credentials().Gen == 2 })
	assert.Equal(t, int64(2), app.logins.Load())
}

// The logged_out redirect and the sampled body regex both trigger.
func TestLiveSession_RedirectAndSampledBody(t *testing.T) {
	app := newFakeApp(t)
	check := defaultCheck()
	check.LoggedOut.RedirectRegex = `(?i)/login\b`
	check.LoggedOut.BodyRegex = `session expired`
	check.SampleEvery = 2
	ls, _, log := newLive(t, app.session(check, nil), LiveOptions{})

	// Probe says logged in each time, so every trigger returns to valid; the
	// cooldown is sidestepped with a clock that never repeats.
	app.probeLogIn.Store(true)
	ls.Observe(1, 302, http.Header{"Location": []string{"/login?next=/x"}}, nil)
	waitUntil(t, "redirect suspect", func() bool { return len(log.kinds()) == 1 && ls.State() == LiveValid })
	ls.confirmedAt.Store(0)

	body := []byte("<p>Your session expired</p>")
	ls.Observe(1, 200, http.Header{}, body) // sample counter 2: body checked
	waitUntil(t, "body suspect", func() bool { return len(log.kinds()) == 2 && ls.State() == LiveValid })
	ls.confirmedAt.Store(0)
	ls.Observe(1, 200, http.Header{}, body) // 3: body not sampled
	time.Sleep(20 * time.Millisecond)
	assert.Len(t, log.kinds(), 2)
	log.mu.Lock()
	assert.Equal(t, "redirect", log.evs[0].Reason)
	assert.Equal(t, "body", log.evs[1].Reason)
	log.mu.Unlock()
}

// The proactive probe notices a logout with no scan traffic at all.
func TestLiveSession_IntervalProbe(t *testing.T) {
	app := newFakeApp(t)
	check := defaultCheck()
	check.Interval = Duration(10 * time.Millisecond)
	ls, _, log := newLive(t, app.session(check, nil), LiveOptions{})
	app.expire()
	waitUntil(t, "interval relogin", func() bool { return ls.Credentials().Gen == 2 })
	waitUntil(t, "valid", func() bool { return ls.State() == LiveValid })
	log.mu.Lock()
	assert.Equal(t, "interval", log.evs[0].Reason)
	log.mu.Unlock()
	ls.Close()
	logins := app.logins.Load()
	app.expire()
	time.Sleep(40 * time.Millisecond)
	assert.Equal(t, logins, app.logins.Load(), "Close stops the timer")
}

// Reauth disabled (or static headers): a confirmed logout is lost at once.
func TestLiveSession_ReauthDisabledGoesStraightToLost(t *testing.T) {
	app := newFakeApp(t)
	off := false
	ls, _, log := newLive(t, app.session(defaultCheck(), &SessionReauth{Enabled: &off, OnFailure: ReauthAbort}), LiveOptions{})
	app.expire()
	ls.Observe(1, 401, http.Header{}, nil)
	waitUntil(t, "lost", func() bool { return ls.State() == LiveFailed })
	assert.Equal(t, []string{"suspect", "lost"}, log.kinds())
	assert.Equal(t, int64(1), app.logins.Load())
	log.mu.Lock()
	assert.Equal(t, ReauthAbort, log.evs[1].OnFailure)
	log.mu.Unlock()
}

// An explicitly pinned header (-H) is never carried by the live credentials.
func TestLiveSession_PinnedHeaderNotOwned(t *testing.T) {
	app := newFakeApp(t)
	ls, _, _ := newLive(t, app.session(defaultCheck(), nil), LiveOptions{Pinned: []string{"cookie"}})
	_, owned := ls.Credentials().Headers["Cookie"]
	assert.False(t, owned)
}

// rehydrate runs on a clone: the manager's session keeps its headers.
func TestManagerRehydrate_DoesNotMutateSession(t *testing.T) {
	app := newFakeApp(t)
	sess := app.session(defaultCheck(), nil)
	m, err := NewManager([]*Session{sess})
	require.NoError(t, err)
	require.NoError(t, m.HydrateSessions())
	require.Equal(t, "sid=1", sess.Headers["Cookie"])

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h, _, err := m.rehydrate(context.Background(), "admin")
			assert.NoError(t, err)
			assert.True(t, strings.HasPrefix(h["Cookie"], "sid="))
		}()
	}
	wg.Wait()
	assert.Equal(t, "sid=1", sess.Headers["Cookie"])
	_, _, err = m.rehydrate(context.Background(), "nobody")
	assert.Error(t, err)
}
