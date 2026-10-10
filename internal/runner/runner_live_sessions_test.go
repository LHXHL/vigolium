package runner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
// app whose session timed out does. GET /api/me is the check probe.
type expiringApp struct {
	srv    *httptest.Server
	logins atomic.Int64
	mu     sync.Mutex
	uses   map[string]int
}

const sessionLife = 100

func newExpiringApp(t *testing.T) *expiringApp {
	t.Helper()
	a := &expiringApp{uses: map[string]int{}}
	a.srv = httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.URL.Path == "/login" {
			n := a.logins.Add(1)
			stdhttp.SetCookie(w, &stdhttp.Cookie{Name: "sid", Value: fmt.Sprint(n), Path: "/"})
			_, _ = w.Write([]byte("welcome"))
			return
		}
		c, err := r.Cookie("sid")
		a.mu.Lock()
		valid := false
		if err == nil && c.Value == fmt.Sprint(a.logins.Load()) {
			if r.URL.Path != "/api/me" {
				a.uses[c.Value]++
			}
			valid = a.uses[c.Value] <= sessionLife
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

// burstModule sends perItem requests to the target for every item.
type burstModule struct{ perItem int }

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
		resp, _, err := client.Execute(rr, http.Options{NoClustering: true})
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
// dynamic-assessment executor drives ~600 requests through the assessment
// requester at an app that expires its session cookie every 100 requests. The
// session logs in again each time (auth.relogin ok:true), pause_traffic keeps
// the logged-out window to the requests already in flight, and the phase
// reports what was lost.
func TestLiveSession_ExecutorReloginsExpiringApp(t *testing.T) {
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

	daRequester, err := r.assessmentRequester(infra)
	require.NoError(t, err)

	tracker := r.beginPhase(context.Background(), string(PhaseDynamicAssessment), infra.httpRequester)
	r.currentPhase.Store(tracker)
	infra.sessions.trackPhase(tracker)

	var items []*httpmsg.HttpRequestResponse
	for i := 0; i < 100; i++ {
		rr, err := httpmsg.GetRawRequestFromURL(fmt.Sprintf("%s/app/%d", app.srv.URL, i))
		require.NoError(t, err)
		items = append(items, rr)
	}
	exec := core.NewExecutor(core.ExecutorConfig{Workers: 8, HTTPRequester: daRequester},
		source.NewSliceSource(items, nil), []modules.ActiveModule{&burstModule{perItem: 5}}, nil)
	_, err = exec.Execute(context.Background())
	require.NoError(t, err)
	out := tracker.finish(context.Background(), nil)
	r.currentPhase.Store(nil)

	var relogins, suspects int
	for _, ev := range decodeEvents(t, &buf) {
		switch ev.Type {
		case scanevents.TypeAuthRelogin:
			require.NotNil(t, ev.OK)
			assert.True(t, *ev.OK, "relogin failed: %s", ev.Message)
			assert.Equal(t, "admin", ev.Session)
			assert.Greater(t, ev.Gen, uint64(1))
			relogins++
		case scanevents.TypeAuthSessionSuspect:
			suspects++
		}
	}
	t.Logf("relogins=%d suspects=%d logins=%d logged_out=%d observed=%d", relogins, suspects, app.logins.Load(), live.LoggedOutResponses(), live.Observed())
	assert.GreaterOrEqual(t, relogins, 1, "at least one auth.relogin ok:true")
	assert.GreaterOrEqual(t, suspects, relogins)
	assert.Equal(t, authentication.LiveValid, live.State())
	assert.LessOrEqual(t, live.LoggedOutResponses(), int64(authentication.DefaultCheckSampleEvery)*int64(relogins),
		"pause_traffic bounds the logged-out window to the requests in flight")
	assert.NotContains(t, out.Reasons, database.ReasonAuthLost)
	if live.LoggedOutResponses() > 0 {
		assert.Contains(t, out.Limits, database.LimitResponsesWhileLoggedOut)
		assert.Equal(t, live.LoggedOutResponses(), out.Counts[CountResponsesWhileLoggedOut])
	}

	// The nuclei snapshot taken now carries the current generation's cookie.
	cookie := live.Credentials().Headers["Cookie"]
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
