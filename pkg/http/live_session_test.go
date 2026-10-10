package http

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/authentication"
	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

// liveApp mints sid=<n> on /login and answers 401 elsewhere once the current
// sid is retired; it records the Cookie and X-Trace of every /app request.
type liveApp struct {
	srv     *httptest.Server
	logins  atomic.Int64
	current atomic.Int64
	mu      sync.Mutex
	cookies []string
}

func newLiveApp(t *testing.T) *liveApp {
	t.Helper()
	a := &liveApp{}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			n := a.logins.Add(1)
			a.current.Store(n)
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: fmt.Sprint(n), Path: "/"})
		default:
			a.mu.Lock()
			a.cookies = append(a.cookies, r.Header.Get("Cookie"))
			a.mu.Unlock()
			if r.Header.Get("Cookie") != fmt.Sprintf("sid=%d", a.current.Load()) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte("ok"))
		}
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *liveApp) lastCookie() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.cookies) == 0 {
		return ""
	}
	return a.cookies[len(a.cookies)-1]
}

func newLiveRequester(t *testing.T, app *liveApp, headers []string, pinned []string) (*Requester, *authentication.LiveSession) {
	t.Helper()
	opts := types.DefaultOptions()
	opts.Headers = headers
	require.NoError(t, network.Init(opts))
	r, err := NewRequester(opts, &services.Services{Options: opts})
	require.NoError(t, err)

	sess := &authentication.Session{
		Name:  "admin",
		Login: &authentication.LoginFlow{URL: app.srv.URL + "/login", Method: "POST", Type: authentication.LoginTypeCookie},
		Check: &authentication.SessionCheck{
			URL:       "/me",
			LoggedIn:  &authentication.LoggedInRule{Status: []int{200}},
			LoggedOut: &authentication.LoggedOutRule{Status: []int{401}},
		},
	}
	m, err := authentication.NewManager([]*authentication.Session{sess})
	require.NoError(t, err)
	require.NoError(t, m.HydrateSessions())
	live, err := authentication.NewLiveSession(sess, authentication.LiveOptions{Manager: m, Pinned: pinned})
	require.NoError(t, err)
	t.Cleanup(live.Close)
	return r.WithLiveSession(live), live
}

func sendTo(t *testing.T, r *Requester, url string) int {
	t.Helper()
	rr, err := httpmsg.GetRawRequestFromURL(url)
	require.NoError(t, err)
	resp, _, err := r.Execute(rr, Options{NoClustering: true})
	require.NoError(t, err)
	defer resp.Close()
	return resp.Response().StatusCode
}

// The requester sends the live credentials, feeds every response to the
// session, and after a re-login sends the new ones.
func TestRequester_LiveSessionAppliesAndObserves(t *testing.T) {
	app := newLiveApp(t)
	r, live := newLiveRequester(t, app, nil, nil)

	assert.Equal(t, 200, sendTo(t, r, app.srv.URL+"/app"))
	assert.Equal(t, "sid=1", app.lastCookie())
	assert.Equal(t, int64(1), live.Observed())

	app.current.Store(-1) // the server forgets the session
	assert.Equal(t, 401, sendTo(t, r, app.srv.URL+"/app"))
	deadline := time.Now().Add(5 * time.Second)
	for live.Credentials().Gen != 2 || live.State() != authentication.LiveValid {
		if time.Now().After(deadline) {
			t.Fatalf("no re-login: state=%s gen=%d", live.State(), live.Credentials().Gen)
		}
		time.Sleep(2 * time.Millisecond)
	}
	assert.Equal(t, 200, sendTo(t, r, app.srv.URL+"/app"))
	assert.Equal(t, "sid=2", app.lastCookie())

	// Views share the live session.
	assert.Same(t, live, r.WithLane(1).LiveSession())
}

// A credential-stripped view (authz modules) never reports to the session, so
// its deliberate 401s cannot trigger a re-login.
func TestRequester_StrippedViewNeverObserves(t *testing.T) {
	app := newLiveApp(t)
	r, live := newLiveRequester(t, app, nil, nil)
	anon, err := r.CloneWithoutCredentials()
	require.NoError(t, err)
	require.Nil(t, anon.LiveSession())

	for i := 0; i < 5; i++ {
		assert.Equal(t, 401, sendTo(t, anon, app.srv.URL+"/app"))
	}
	assert.Equal(t, "", app.lastCookie(), "the stripped view sends no session cookie")
	assert.Equal(t, int64(0), live.Observed())
	assert.Equal(t, int64(0), live.LoggedOutResponses())
	assert.Equal(t, authentication.LiveValid, live.State())
	assert.Equal(t, int64(1), app.logins.Load())
}

// An explicit -H of a header the session owns still wins.
func TestRequester_LiveSessionExplicitHeaderWins(t *testing.T) {
	app := newLiveApp(t)
	r, _ := newLiveRequester(t, app, []string{"Cookie: operator=1"}, []string{"Cookie"})
	sendTo(t, r, app.srv.URL+"/app")
	assert.Equal(t, "operator=1", app.lastCookie())
}
