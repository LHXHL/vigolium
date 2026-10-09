package graphql_scan

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

const csrfObservedOp = `{"query":"query Me { me { id email } }","operationName":"Me"}`

// csrfServerOpts configures which request shapes the fake GraphQL server
// executes. JSON POSTs are always accepted.
type csrfServerOpts struct {
	acceptGET, acceptForm, acceptTextPlain bool
	rejectForeignOrigin                    bool
	public                                 bool // `me` resolves without the cookie
}

// csrfServer is a GraphQL endpoint at /graphql whose `me` field requires the
// session=abc cookie. nonJSON counts requests that arrived in a forgeable shape.
func csrfServer(t *testing.T, o csrfServerOpts, nonJSON *atomic.Int64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/graphql" {
			http.NotFound(w, r)
			return
		}
		ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		var query string
		switch {
		case r.Method == http.MethodGet:
			nonJSON.Add(1)
			if !o.acceptGET {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			query = r.URL.Query().Get("query")
		case ct == "application/json" || (ct == "text/plain" && o.acceptTextPlain):
			if ct == "text/plain" {
				nonJSON.Add(1)
			}
			var body struct {
				Query string `json:"query"`
			}
			raw, _ := io.ReadAll(r.Body)
			if json.Unmarshal(raw, &body) != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			query = body.Query
		case ct == "application/x-www-form-urlencoded" && o.acceptForm:
			nonJSON.Add(1)
			raw, _ := io.ReadAll(r.Body)
			v, _ := url.ParseQuery(string(raw))
			query = v.Get("query")
		default:
			nonJSON.Add(1)
			w.WriteHeader(http.StatusUnsupportedMediaType)
			_, _ = w.Write([]byte(`{"errors":[{"message":"unsupported content type"}]}`))
			return
		}
		if o.rejectForeignOrigin && r.Header.Get("Origin") != "" && !strings.Contains(r.Header.Get("Origin"), r.Host) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":[{"message":"bad origin"}]}`))
			return
		}
		switch {
		case strings.TrimSpace(query) == "{ __typename }":
			_, _ = w.Write([]byte(`{"data":{"__typename":"Query"}}`))
		case strings.Contains(query, "me {"):
			c, err := r.Cookie("session")
			if o.public || (err == nil && c.Value == "abc") {
				_, _ = w.Write([]byte(`{"data":{"me":{"id":"1","email":"alice@example.test"}}}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":{"me":null},"errors":[{"message":"unauthenticated"}]}`))
		default:
			_, _ = w.Write([]byte(`{"errors":[{"message":"Cannot query field"}]}`))
		}
	}))
}

// csrfSeed is the observed authenticated GraphQL request (Cookie session=abc)
// with a captured response that set the session cookie with setCookie ("" for
// none observed).
func csrfSeed(t *testing.T, srvURL, setCookie string) *httpmsg.HttpRequestResponse {
	t.Helper()
	base := modtest.RequestJSON(t, srvURL+"/graphql", csrfObservedOp)
	raw, err := httpmsg.AddOrReplaceHeader(base.Request().Raw(), "Cookie", "session=abc; theme=dark")
	require.NoError(t, err)
	raw, err = httpmsg.AddOrReplaceHeader(raw, "X-CSRF-Token", "not-forgeable")
	require.NoError(t, err)
	req := httpmsg.NewHttpRequestWithService(base.Service(), raw)
	respRaw := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
	if setCookie != "" {
		respRaw += "Set-Cookie: " + setCookie + "\r\n"
	}
	body := `{"data":{"me":{"id":"1","email":"alice@example.test"}}}`
	respRaw += fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(body), body)
	return httpmsg.NewHttpRequestResponse(req, httpmsg.NewHttpResponse([]byte(respRaw)))
}

func runCSRF(t *testing.T, o csrfServerOpts, setCookie string) (*output.ResultEvent, int64) {
	t.Helper()
	var nonJSON atomic.Int64
	srv := csrfServer(t, o, &nonJSON)
	defer srv.Close()
	ctx := csrfSeed(t, srv.URL, setCookie)
	res := New().phaseCSRF(ctx, modtest.Requester(t), &modkit.ScanContext{}, "/graphql", nil, srv.URL)
	return res, nonJSON.Load()
}

var allForgeable = csrfServerOpts{acceptGET: true, acceptForm: true, acceptTextPlain: true}

func TestPhaseCSRF_FindingWhenFormPOSTAcceptedAndNoSameSite(t *testing.T) {
	t.Parallel()
	res, _ := runCSRF(t, allForgeable, "session=abc; Path=/; HttpOnly")
	require.NotNil(t, res, "cookie-authenticated op executed via forgeable shapes must be reported")
	assert.Equal(t, output.RecordKindFinding, res.RecordKind)
	assert.Equal(t, output.EvidenceGradeBypass, res.EvidenceGrade)
	assert.Equal(t, []string{"GET ?query=", "POST application/x-www-form-urlencoded", "POST text/plain"}, res.Metadata["accepted_transports"])
	assert.Equal(t, true, res.Metadata["samesite_observed"])
	assert.Contains(t, res.Request, "Origin: "+csrfForeignOrigin)
	assert.NotContains(t, res.Request, "X-CSRF-Token", "forged requests must not carry headers a cross-site page cannot set")
	assert.Contains(t, strings.Join(res.ExtractedResults, "\n"), "observed request")
}

func TestPhaseCSRF_SameSiteLaxOrStrictSuppresses(t *testing.T) {
	t.Parallel()
	for _, attr := range []string{"Lax", "Strict"} {
		res, sent := runCSRF(t, allForgeable, "session=abc; Path=/; SameSite="+attr)
		assert.Nilf(t, res, "SameSite=%s session cookie must suppress the finding", attr)
		assert.Zerof(t, sent, "SameSite=%s: no forged requests should be sent", attr)
	}
}

func TestPhaseCSRF_JSONOnlyEndpointIsClean(t *testing.T) {
	t.Parallel()
	res, sent := runCSRF(t, csrfServerOpts{}, "session=abc; Path=/")
	assert.Nil(t, res)
	assert.NotZero(t, sent, "the forgeable shapes should have been tried")
}

func TestPhaseCSRF_PublicOperationIsNotForgeable(t *testing.T) {
	t.Parallel()
	o := allForgeable
	o.public = true
	res, sent := runCSRF(t, o, "session=abc; Path=/")
	assert.Nil(t, res, "an operation that returns the same data without the cookie has nothing to forge")
	assert.Zero(t, sent, "the cookie control must stop the phase before any forged request")
}

func TestPhaseCSRF_OriginCheckOnPOSTBlocks(t *testing.T) {
	t.Parallel()
	o := csrfServerOpts{acceptForm: true, acceptTextPlain: true, rejectForeignOrigin: true}
	res, _ := runCSRF(t, o, "session=abc; Path=/")
	assert.Nil(t, res, "an endpoint that rejects foreign Origins on POST is not CSRF-able")
}

func TestPhaseCSRF_GETOnlyIsCandidate(t *testing.T) {
	t.Parallel()
	res, _ := runCSRF(t, csrfServerOpts{acceptGET: true}, "session=abc; Path=/")
	require.NotNil(t, res)
	assert.Equal(t, output.RecordKindCandidate, res.RecordKind)
	assert.Equal(t, false, res.Metadata["post_transport"])
}

func TestPhaseCSRF_UnobservedCookiePostureIsCandidate(t *testing.T) {
	t.Parallel()
	res, _ := runCSRF(t, allForgeable, "")
	require.NotNil(t, res)
	assert.Equal(t, output.RecordKindCandidate, res.RecordKind)
	assert.Equal(t, false, res.Metadata["samesite_observed"])
}

func TestPhaseCSRF_NoCookieNoProbe(t *testing.T) {
	t.Parallel()
	var nonJSON atomic.Int64
	var total atomic.Int64
	inner := csrfServer(t, allForgeable, &nonJSON)
	defer inner.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		total.Add(1)
		inner.Config.Handler.ServeHTTP(w, r)
	}))
	defer srv.Close()

	ctx := modtest.RequestJSON(t, srv.URL+"/graphql", csrfObservedOp)
	res := New().phaseCSRF(ctx, modtest.Requester(t), &modkit.ScanContext{}, "/graphql", nil, srv.URL)
	assert.Nil(t, res)
	assert.Zero(t, total.Load(), "without a session cookie there is nothing to forge")
}

// The full scan discovers the endpoint and runs the CSRF phase.
func TestScanPerRequest_ReportsGraphQLCSRF(t *testing.T) {
	t.Parallel()
	var nonJSON atomic.Int64
	srv := csrfServer(t, allForgeable, &nonJSON)
	defer srv.Close()

	res, err := New().ScanPerRequest(csrfSeed(t, srv.URL, "session=abc; Path=/"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	var found bool
	for _, r := range res {
		if r.Info.Name == "GraphQL Cross-Site Request Forgery" {
			found = true
			assert.Equal(t, output.RecordKindFinding, r.RecordKind)
		}
	}
	assert.True(t, found, "expected the CSRF finding from the full scan, got %+v", res)
}

func TestIsMutation(t *testing.T) {
	assert.True(t, isMutation("mutation { a }"))
	assert.True(t, isMutation("  # c\nmutation Do { a }"))
	assert.True(t, isMutation("subscription { a }"))
	assert.False(t, isMutation("query { a }"))
	assert.False(t, isMutation("{ a }"))
}

func TestCSRFOperations_SkipsObservedMutationUnlessDeep(t *testing.T) {
	ctx := modtest.RequestJSON(t, "http://127.0.0.1:1/graphql", `{"query":"mutation { deleteAll }"}`)
	assert.Empty(t, csrfOperations(ctx, nil, false))
	ops := csrfOperations(ctx, nil, true)
	require.Len(t, ops, 1)
	assert.Equal(t, "observed request", ops[0].source)
}
