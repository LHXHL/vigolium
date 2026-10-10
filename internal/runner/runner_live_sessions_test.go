package runner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	stdhttp "net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/authentication"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// expiringApp issues sid=<n> on POST /login and honours each sid for
// sessionLife requests; after that every request carrying it gets 401, as an
// app whose session timed out does. A sid replaced by a later login gets 401
// too. GET /api/me is the check probe and does not use the session up.
type expiringApp struct {
	srv    *httptest.Server
	logins atomic.Int64
	mu     sync.Mutex
	// Per sid, the scan requests (not probes) that were honoured and that
	// were refused.
	ok, refused map[string]int
}

const sessionLife = 100

func newExpiringApp(t *testing.T) *expiringApp {
	t.Helper()
	a := &expiringApp{ok: map[string]int{}, refused: map[string]int{}}
	a.srv = httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.URL.Path == "/login" {
			a.mu.Lock()
			n := a.logins.Add(1)
			a.mu.Unlock()
			stdhttp.SetCookie(w, &stdhttp.Cookie{Name: "sid", Value: fmt.Sprint(n), Path: "/"})
			_, _ = w.Write([]byte("welcome"))
			return
		}
		sid := ""
		if c, err := r.Cookie("sid"); err == nil {
			sid = c.Value
		}
		probe := r.URL.Path == "/api/me"
		a.mu.Lock()
		valid := sid != "" && sid == fmt.Sprint(a.logins.Load()) && a.ok[sid] < sessionLife
		if !probe {
			if valid {
				a.ok[sid]++
			} else {
				a.refused[sid]++
			}
		}
		a.mu.Unlock()
		if !valid {
			w.WriteHeader(stdhttp.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"email":"admin@example.test"}`))
	}))
	t.Cleanup(a.srv.Close)
	return a
}

// books returns copies of the per-sid honoured and refused counts.
func (a *expiringApp) books() (ok, refused map[string]int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return maps.Clone(a.ok), maps.Clone(a.refused)
}

func writeAuthFile(t *testing.T, app *expiringApp, onFailure string) string {
	t.Helper()
	body := fmt.Sprintf(`name: admin
role: primary
login:
  url: %s/login
  method: POST
  type: cookie
check:
  url: /api/me
  logged_in:
    status: [200]
  logged_out:
    status: [401]
reauth:
  max_attempts: 2
  backoff: 1s
  on_failure: %s
`, app.srv.URL, onFailure)
	p := filepath.Join(t.TempDir(), "admin.yaml")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	return p
}

// burstModule sends perItem requests to the target for every item, one at a
// time, and records the most of its requests in flight at once.
type burstModule struct {
	perItem             int
	inFlight, maxFlight atomic.Int64
}

func (m *burstModule) ID() string                      { return "test-burst" }
func (m *burstModule) Name() string                    { return "test-burst" }
func (m *burstModule) Description() string             { return "" }
func (m *burstModule) ShortDescription() string        { return "" }
func (m *burstModule) ConfirmationCriteria() string    { return "" }
func (m *burstModule) Severity() severity.Severity     { return 0 }
func (m *burstModule) Confidence() severity.Confidence { return 0 }
func (m *burstModule) ScanScopes() modules.ScanScope   { return modules.ScanScopeRequest }
func (m *burstModule) Tags() []string                  { return nil }
func (m *burstModule) AllowedInsertionPointTypes() modules.InsertionPointTypeSet {
	return modules.AllInsertionPointTypes
}
func (m *burstModule) CanProcess(*httpmsg.HttpRequestResponse) bool { return true }
func (m *burstModule) ScanPerInsertionPoint(*httpmsg.HttpRequestResponse, httpmsg.InsertionPoint, *http.Requester, *modules.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}
func (m *burstModule) ScanPerHost(*httpmsg.HttpRequestResponse, *http.Requester, *modules.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}
func (m *burstModule) ScanPerRequest(item *httpmsg.HttpRequestResponse, client *http.Requester, _ *modules.ScanContext) ([]*output.ResultEvent, error) {
	for i := 0; i < m.perItem; i++ {
		u, _ := item.URL()
		rr, err := httpmsg.GetRawRequestFromURL(fmt.Sprintf("%s?probe=%d", u.String(), i))
		if err != nil {
			return nil, err
		}
		n := m.inFlight.Add(1)
		for cur := m.maxFlight.Load(); n > cur && !m.maxFlight.CompareAndSwap(cur, n); cur = m.maxFlight.Load() {
		}
		resp, _, err := client.Execute(rr, http.Options{NoClustering: true})
		m.inFlight.Add(-1)
		if err != nil {
			return nil, err
		}
		resp.Close()
	}
	return nil, nil
}

func decodeEvents(t *testing.T, buf *bytes.Buffer) []scanevents.Event {
	t.Helper()
	var out []scanevents.Event
	sc := bufio.NewScanner(bytes.NewReader(buf.Bytes()))
	for sc.Scan() {
		var ev scanevents.Event
		require.NoError(t, json.Unmarshal(sc.Bytes(), &ev))
		out = append(out, ev)
	}
	return out
}

// TestLiveSession_ExecutorReloginsExpiringApp is the end-to-end case: a
// dynamic-assessment executor drives 500 requests through the assessment
// requester at an app that expires its session cookie every 100 requests. The
// session logs in again exactly once per expiry (auth.relogin ok:true),
// pause_traffic holds every request not already in flight from the first 401
// until the new cookie is in place, and the phase reports what was lost.
//
// Nothing here depends on timing. At most activeTasks requests are between
// the requester's Wait and its Observe at once, so each expiry costs at most
// that many refused responses; with 500 requests and a 100-request session
// that fixes the run at exactly four expiries (the fifth cookie serves the
// last <=96 requests and never expires). The fourth relogin finishes while
// requests are parked, and parked requests resume only after the relogin is
// reported, so every event is in buf when Execute returns.
func TestLiveSession_ExecutorReloginsExpiringApp(t *testing.T) {
	const (
		items, perItem = 100, 5
		total          = items * perItem
		activeTasks    = 8 // each burst task sends one request at a time
		wantRelogins   = total/sessionLife - 1
	)
	app := newExpiringApp(t)
	var buf bytes.Buffer
	prev := scanevents.Default()
	scanevents.Install(scanevents.New(&buf, "scan-live"))
	t.Cleanup(func() { scanevents.Install(prev) })

	opts := types.DefaultOptions()
	opts.AuthFiles = []string{writeAuthFile(t, app, "continue")}
	opts.Targets = []string{app.srv.URL}
	opts.Silent = true
	r, infra := newSessionTestRunner(t, opts, config.SessionStrategyConfig{UseInDiscovery: true, CompareEnabled: true})
	t.Cleanup(infra.sessions.close)

	require.NoError(t, r.initSessions(context.Background(), infra))
	live := infra.sessions.primaryLive()
	require.NotNil(t, live, "a session with a check block is kept live")
	require.Same(t, live, infra.httpRequester.LiveSession())
	require.Equal(t, int64(1), app.logins.Load())

	daRequester, err := r.assessmentRequester(infra)
	require.NoError(t, err)

	tracker := r.beginPhase(context.Background(), string(PhaseDynamicAssessment), infra.httpRequester)
	r.currentPhase.Store(tracker)
	infra.sessions.trackPhase(tracker)

	var reqs []*httpmsg.HttpRequestResponse
	for i := 0; i < items; i++ {
		rr, err := httpmsg.GetRawRequestFromURL(fmt.Sprintf("%s/app/%d", app.srv.URL, i))
		require.NoError(t, err)
		// An attached response makes SkipBaseline skip the baseline fetch, so
		// the only scan traffic is the module's own: total requests, at most
		// activeTasks at a time.
		reqs = append(reqs, rr.WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))))
	}
	burst := &burstModule{perItem: perItem}
	exec := core.NewExecutor(core.ExecutorConfig{Workers: 8, ActiveTaskLimit: activeTasks, SkipBaseline: true, HTTPRequester: daRequester},
		source.NewSliceSource(reqs, nil), []modules.ActiveModule{burst}, nil)
	_, err = exec.Execute(context.Background())
	require.NoError(t, err)
	out := tracker.finish(context.Background(), nil)
	r.currentPhase.Store(nil)

	ok, refused := app.books()
	t.Logf("logins=%d ok=%v refused=%v logged_out=%d observed=%d max_in_flight=%d",
		app.logins.Load(), ok, refused, live.LoggedOutResponses(), live.Observed(), burst.maxFlight.Load())
	require.LessOrEqual(t, burst.maxFlight.Load(), int64(activeTasks), "the executor bounds requests in flight")
	require.Equal(t, int64(total), live.Observed(), "every scan response reached the session")

	var relogins, suspects []uint64
	for _, ev := range decodeEvents(t, &buf) {
		switch ev.Type {
		case scanevents.TypeAuthRelogin:
			require.NotNil(t, ev.OK)
			assert.True(t, *ev.OK, "relogin failed: %s", ev.Message)
			assert.Equal(t, "admin", ev.Session)
			relogins = append(relogins, ev.Gen)
		case scanevents.TypeAuthSessionSuspect:
			suspects = append(suspects, ev.Gen)
		}
	}

	// Exactly one confirm and one login per expiry, in generation order.
	var wantGens, wantSuspects []uint64
	for g := uint64(1); g <= wantRelogins; g++ {
		wantSuspects = append(wantSuspects, g)
		wantGens = append(wantGens, g+1)
	}
	assert.Equal(t, wantSuspects, suspects, "one auth.session_suspect per expired generation")
	assert.Equal(t, wantGens, relogins, "one auth.relogin ok:true per expiry, each minting the next generation")
	assert.Equal(t, int64(wantRelogins+1), app.logins.Load(), "the app saw one login per expiry, plus the first")
	assert.Equal(t, authentication.LiveValid, live.State())

	// Each replaced cookie was used for its whole life before it was
	// replaced, and every request it lost was already in flight when the
	// session noticed: the rest waited and went out with the next cookie.
	var lost int
	for g := 1; g <= wantRelogins; g++ {
		sid := fmt.Sprint(g)
		assert.Equal(t, sessionLife, ok[sid], "sid=%s served its whole life", sid)
		assert.GreaterOrEqual(t, refused[sid], 1, "sid=%s expired", sid)
		assert.LessOrEqual(t, refused[sid], activeTasks,
			"pause_traffic bounds sid=%s's logged-out window to the requests in flight", sid)
		lost += refused[sid]
	}
	last := fmt.Sprint(wantRelogins + 1)
	assert.Zero(t, refused[last], "nothing sent with the current cookie was refused")
	assert.Equal(t, total-wantRelogins*sessionLife-lost, ok[last], "the rest went out with the current cookie")
	assert.NotContains(t, refused, "", "no request went out without a cookie")

	// The session counted the same refusals the app made, and the phase reports them.
	assert.Equal(t, int64(lost), live.LoggedOutResponses())
	assert.NotContains(t, out.Reasons, database.ReasonAuthLost)
	assert.Contains(t, out.Limits, database.LimitResponsesWhileLoggedOut)
	assert.Equal(t, int64(lost), out.Counts[CountResponsesWhileLoggedOut])

	// The nuclei snapshot taken now carries the current generation's cookie.
	cookie := live.Credentials().Headers["Cookie"]
	assert.Equal(t, "sid="+last, cookie)
	var cookies []string
	for _, h := range r.assessmentHeaderSlice(infra) {
		if strings.HasPrefix(strings.ToLower(h), "cookie:") {
			cookies = append(cookies, h)
		}
	}
	assert.Equal(t, []string{"Cookie: " + cookie}, cookies)
}

// An explicit -H of a header the session owns wins over the live credentials.
func TestLiveSession_ExplicitHeaderPinned(t *testing.T) {
	app := newExpiringApp(t)
	opts := types.DefaultOptions()
	opts.AuthFiles = []string{writeAuthFile(t, app, "continue")}
	opts.Targets = []string{app.srv.URL}
	opts.Headers = []string{"Cookie: operator=1"}
	r, infra := newSessionTestRunner(t, opts, config.SessionStrategyConfig{UseInDiscovery: false, CompareEnabled: true})
	t.Cleanup(infra.sessions.close)
	require.NoError(t, r.initSessions(context.Background(), infra))

	live := infra.sessions.primaryLive()
	require.NotNil(t, live)
	_, owned := live.Credentials().Headers["Cookie"]
	assert.False(t, owned, "the operator's -H Cookie is pinned")
	assert.False(t, hasHeader(infra.assessmentHeaders, "Cookie"), "the frozen session cookie must not shadow -H")
	view, err := r.assessmentRequester(infra)
	require.NoError(t, err)
	assert.Same(t, live, view.LiveSession())
	assert.Nil(t, infra.httpRequester.LiveSession(), "use_in_discovery: false keeps the session off discovery")
}

// reauth.on_failure: abort cancels the scan with *AuthLostError (login_failed),
// and the phases it stops are attributed to auth_lost.
func TestLiveSession_AbortCancelsScan(t *testing.T) {
	r := &Runner{options: types.DefaultOptions()}
	r.options.Silent = true
	ctx, stop := r.armAuthAbort(context.Background())
	defer stop()
	tracker := r.beginPhase(ctx, string(PhaseDynamicAssessment), nil)
	r.currentPhase.Store(tracker)

	r.onLiveSessionEvent(authentication.LiveEvent{Kind: authentication.LiveEventLost, Session: "admin",
		OnFailure: authentication.ReauthAbort, Err: errors.New("login returned status 500")})

	lost := authLostCause(ctx)
	require.NotNil(t, lost)
	assert.Equal(t, "admin", lost.Session)
	assert.Equal(t, apicontract.CodeLoginFailed, lost.Code())
	assert.Equal(t, database.ReasonAuthLost, contextStopReason(ctx))
	assert.Equal(t, database.ReasonAuthLost, scanStopReason(ctx, context.Background()))
	out := tracker.finish(ctx, nil)
	assert.Contains(t, out.Reasons, database.ReasonAuthLost)
}

// on_failure: continue marks the phase partial and keeps the scan running.
func TestLiveSession_ContinueMarksAuthLost(t *testing.T) {
	r := &Runner{options: types.DefaultOptions()}
	r.options.Silent = true
	ctx, stop := r.armAuthAbort(context.Background())
	defer stop()
	tracker := r.beginPhase(ctx, string(PhaseDynamicAssessment), nil)
	r.currentPhase.Store(tracker)

	r.onLiveSessionEvent(authentication.LiveEvent{Kind: authentication.LiveEventLost, Session: "admin",
		OnFailure: authentication.ReauthContinue})
	assert.NoError(t, ctx.Err())
	out := tracker.finish(ctx, nil)
	assert.Contains(t, out.Reasons, database.ReasonAuthLost)
	assert.Equal(t, database.PhasePartial, out.State)
}
