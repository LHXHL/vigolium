package password_reset_poisoning

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/oast/oastclass"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// Confirmation is an out-of-band callback from the emailed link, which
// httptest cannot emulate; these tests cover request selection, the planted
// headers, the once-per-endpoint budget and the routing fallback against a
// fake OAST provider.

func TestMain(m *testing.M) { modtest.VerifyNoLeaks(m) }

type fakeOAST struct {
	mu       sync.Mutex
	unready  bool
	params   []string
	types    []string
	classes  []oastclass.Class
	recorded map[string]string
}

// GenerateURL returns a host derived from the header name so a test can tell
// which header carried which callback host.
func (f *fakeOAST) GenerateURL(_, param, injectionType, _, _ string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.unready {
		return ""
	}
	f.params = append(f.params, param)
	f.types = append(f.types, injectionType)
	return strings.ToLower(param) + ".oast.test"
}

// GenerateURLFor records the class the module rated its callbacks with.
func (f *fakeOAST) GenerateURLFor(cls oastclass.Class, target, param, injectionType, moduleID, reqHash string) string {
	f.mu.Lock()
	f.classes = append(f.classes, cls)
	f.mu.Unlock()
	return f.GenerateURL(target, param, injectionType, moduleID, reqHash)
}

func (f *fakeOAST) RecordPayload(host, payload string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.recorded == nil {
		f.recorded = map[string]string{}
	}
	f.recorded[host] = payload
}

func (f *fakeOAST) Enabled() bool { return true }

// seenReq is what the reset endpoint received.
type seenReq struct {
	host, xfh, xhost, forwarded string
}

type resetServer struct {
	*httptest.Server
	mu   sync.Mutex
	seen []seenReq
}

// newResetServer records every request; reject421 answers 421 Misdirected
// Request when the Host is not the server's own (a vhost-routed front end).
func newResetServer(t *testing.T, reject421 bool) *resetServer {
	t.Helper()
	rs := &resetServer{}
	rs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rs.mu.Lock()
		rs.seen = append(rs.seen, seenReq{r.Host, r.Header.Get("X-Forwarded-Host"), r.Header.Get("X-Host"), r.Header.Get("Forwarded")})
		rs.mu.Unlock()
		if reject421 && strings.HasSuffix(r.Host, ".oast.test") {
			w.WriteHeader(http.StatusMisdirectedRequest)
			return
		}
		_, _ = w.Write([]byte("If the account exists, a reset link was sent."))
	}))
	t.Cleanup(rs.Close)
	return rs
}

func (rs *resetServer) requests() []seenReq {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return append([]seenReq(nil), rs.seen...)
}

func scan(t *testing.T, m *Module, method, url, body string, sc *modkit.ScanContext) {
	t.Helper()
	rr := modtest.RequestMethod(t, method, url, body)
	res, err := m.ScanPerRequest(rr, modtest.Requester(t), sc)
	require.NoError(t, err)
	assert.Empty(t, res, "findings arrive asynchronously via OAST")
}

func TestNew_Metadata(t *testing.T) {
	t.Parallel()
	m := New()
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, severity.High, m.Severity())
	assert.Subset(t, m.Tags(), []string{"risk:high", "moderate", "oast"})
	assert.Equal(t, modkit.ScanScopeRequest, m.ScanScopes())
}

// TestPlantsAllLinkHeadersInOneRequest: a recorded forgot-password POST is
// replayed exactly once with a distinct OAST host in each link-building header.
func TestPlantsAllLinkHeadersInOneRequest(t *testing.T) {
	t.Parallel()
	srv := newResetServer(t, false)
	oast := &fakeOAST{}
	scan(t, New(), "POST", srv.URL+"/forgot-password", "email=victim%40example.com", &modkit.ScanContext{OASTProvider: oast})

	reqs := srv.requests()
	require.Len(t, reqs, 1, "one reset email per endpoint")
	assert.Equal(t, seenReq{
		host:      "host.oast.test",
		xfh:       "x-forwarded-host.oast.test",
		xhost:     "x-host.oast.test",
		forwarded: "host=forwarded.oast.test",
	}, reqs[0])

	oast.mu.Lock()
	defer oast.mu.Unlock()
	assert.ElementsMatch(t, []string{"Host", "X-Forwarded-Host", "X-Host", "Forwarded"}, oast.params)
	assert.Equal(t, "host=forwarded.oast.test", oast.recorded["forwarded.oast.test"], "the planted header value is recorded")
	require.Len(t, oast.classes, 4)
	for _, cls := range oast.classes {
		assert.Equal(t, oastclass.PasswordResetPoisoning, cls)
	}
	for _, typ := range oast.types {
		assert.Contains(t, typ, "header", "the label must mark a header plant so the finding rebuilds the request")
		for _, bad := range []string{"command", "sql", "xxe", "jwt", "smuggle"} {
			assert.NotContains(t, typ, bad)
		}
	}
}

// TestHostRejected_RetriesWithoutHostOverride: when the Host override fails
// vhost routing (421), the reset never ran, so the forwarding headers are sent
// once more with the original Host.
func TestHostRejected_RetriesWithoutHostOverride(t *testing.T) {
	t.Parallel()
	srv := newResetServer(t, true)
	scan(t, New(), "POST", srv.URL+"/api/password/reset", `email=a%40b.io`, &modkit.ScanContext{OASTProvider: &fakeOAST{}})

	reqs := srv.requests()
	require.Len(t, reqs, 2)
	assert.Equal(t, "host.oast.test", reqs[0].host)
	assert.NotContains(t, reqs[1].host, "oast.test", "the retry keeps the original Host")
	assert.Equal(t, "x-forwarded-host.oast.test", reqs[1].xfh)
	assert.Equal(t, "host=forwarded.oast.test", reqs[1].forwarded)
}

// TestOncePerEndpoint: the same endpoint seen again in the scan (another
// recorded request, a different email) is not replayed.
func TestOncePerEndpoint(t *testing.T) {
	t.Parallel()
	srv := newResetServer(t, false)
	mgr := dedup.NewManager()
	defer mgr.Close()
	sc := &modkit.ScanContext{OASTProvider: &fakeOAST{}, DedupManager: mgr}
	m := New()
	scan(t, m, "POST", srv.URL+"/forgot", "username=alice", sc)
	scan(t, m, "POST", srv.URL+"/forgot", "username=bob", sc)
	assert.Len(t, srv.requests(), 1)
}

// TestOASTNotReady_EndpointStaysUntested: while OAST registration is in flight
// nothing is sent and the endpoint is not claimed, so a later pass tests it.
func TestOASTNotReady_EndpointStaysUntested(t *testing.T) {
	t.Parallel()
	srv := newResetServer(t, false)
	mgr := dedup.NewManager()
	defer mgr.Close()
	oast := &fakeOAST{unready: true}
	sc := &modkit.ScanContext{OASTProvider: oast, DedupManager: mgr}
	m := New()
	scan(t, m, "POST", srv.URL+"/forgot", "email=a%40b.io", sc)
	assert.Empty(t, srv.requests())

	oast.mu.Lock()
	oast.unready = false
	oast.mu.Unlock()
	scan(t, m, "POST", srv.URL+"/forgot", "email=a%40b.io", sc)
	assert.Len(t, srv.requests(), 1)
}

// TestSkipsNonResetRequests covers the selection gate: only reset-request
// steps naming an account are replayed.
func TestSkipsNonResetRequests(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, method, path, body string
		sc                       *modkit.ScanContext
	}{
		{"login with email", "POST", "/login", "email=a%40b.io", nil},
		{"reset without account param", "POST", "/forgot-password", "lang=en", nil},
		{"reset completion with new password", "POST", "/reset", "email=a%40b.io&newPassword=x&token=t", nil},
		{"reset page GET without params", "GET", "/forgot-password", "", nil},
		{"no OAST provider", "POST", "/forgot-password", "email=a%40b.io", &modkit.ScanContext{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := newResetServer(t, false)
			sc := tc.sc
			if sc == nil {
				sc = &modkit.ScanContext{OASTProvider: &fakeOAST{}}
			}
			scan(t, New(), tc.method, srv.URL+tc.path, tc.body, sc)
			assert.Empty(t, srv.requests())
		})
	}
}

// TestResetKeywordInBody: a GraphQL-style endpoint whose path is generic but
// whose body requests a reset, with an email-valued field, qualifies.
func TestResetKeywordInBody(t *testing.T) {
	t.Parallel()
	srv := newResetServer(t, false)
	rr := modtest.RequestJSON(t, srv.URL+"/graphql",
		`{"query":"mutation($e:String!){requestPasswordReset(email:$e)}","variables":{"e":"victim@example.com"}}`)
	_, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{OASTProvider: &fakeOAST{}})
	require.NoError(t, err)
	assert.Len(t, srv.requests(), 1)
}

func TestHasIdentityParam_Tokens(t *testing.T) {
	t.Parallel()
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { atomic.AddInt64(&hits, 1) }))
	defer srv.Close()
	for body, want := range map[string]bool{
		"user%5Bemail%5D=x":   true,
		"emailAddress=x":      true,
		"login_name=x":        true,
		"contact=a%40b.io":    true,
		"mailbox_size=1":      false, // "mailbox" is one token, not "mail"
		"q=hello":             false,
		"email=x&pass=hunter": false,
	} {
		rr := modtest.RequestMethod(t, "POST", srv.URL+"/forgot", body)
		points, err := (&modkit.ScanContext{}).GetInsertionPoints(rr.Request().Raw(), rr.Request().ID(), true)
		require.NoError(t, err)
		assert.Equal(t, want, hasIdentityParam(points), body)
	}
	assert.Zero(t, atomic.LoadInt64(&hits))
}
