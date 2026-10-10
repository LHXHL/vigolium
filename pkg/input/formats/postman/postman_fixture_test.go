package postman

import (
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// parseFixture parses testdata/collection_v21.json and returns the requests
// keyed by path (without query), plus the captured log entries.
func parseFixture(t *testing.T, opts Options) (map[string]*httpmsg.HttpRequestResponse, *Format, *observer.ObservedLogs) {
	t.Helper()
	core, logs := observer.New(zapcore.DebugLevel)
	restore := zap.ReplaceGlobals(zap.New(core))
	t.Cleanup(restore)

	f := New()
	f.SetPostmanOptions(opts)
	out := map[string]*httpmsg.HttpRequestResponse{}
	err := f.Parse(filepath.Join("testdata", "collection_v21.json"), func(rr *httpmsg.HttpRequestResponse) bool {
		u, err := rr.URL()
		require.NoError(t, err)
		out[u.Path] = rr
		return true
	})
	require.NoError(t, err)
	return out, f, logs
}

func TestFixture_QueryNotDuplicated(t *testing.T) {
	rrs, _, _ := parseFixture(t, Options{})

	search := rrs["/search"]
	require.NotNil(t, search)
	assert.True(t, strings.HasPrefix(string(search.Request().Raw()), "GET /search?q=shoes&page=2 HTTP/1.1\r\n"),
		string(search.Request().Raw()))

	// raw has no query: enabled url.query entries are merged, disabled dropped.
	list := rrs["/list"]
	require.NotNil(t, list)
	assert.True(t, strings.HasPrefix(string(list.Request().Raw()), "GET /list?limit=5 HTTP/1.1\r\n"),
		string(list.Request().Raw()))
}

func TestFixture_AuthInheritance(t *testing.T) {
	rrs, _, _ := parseFixture(t, Options{})
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:s3cret"))

	cases := []struct {
		path, header, want string
	}{
		{"/search", "Authorization", "Bearer tok-123"},    // collection bearer
		{"/admin/users", "Authorization", basic},          // folder basic
		{"/admin/health", "Authorization", ""},            // request noauth
		{"/admin/export", "Authorization", ""},            // request apikey (query)
		{"/admin/me", "Authorization", "Bearer explicit"}, // explicit header wins
		{"/status", "Authorization", ""},                  // folder noauth stops collection bearer
		{"/login", "X-API-Key", "tok-123"},                // folder apikey header, variable resolved
		{"/login", "Authorization", ""},
	}
	for _, tc := range cases {
		rr := rrs[tc.path]
		require.NotNil(t, rr, tc.path)
		assert.Equal(t, tc.want, rr.Request().Header(tc.header), "%s %s", tc.path, tc.header)
	}

	export := string(rrs["/admin/export"].Request().Raw())
	assert.True(t, strings.HasPrefix(export, "GET /admin/export?api_key=k-999 HTTP/1.1\r\n"), export)
	assert.Equal(t, 1, strings.Count(string(rrs["/admin/me"].Request().Raw()), "Authorization:"))
}

func TestFixture_BodyModes(t *testing.T) {
	rrs, _, _ := parseFixture(t, Options{})

	login := rrs["/login"].Request()
	assert.Equal(t, "application/x-www-form-urlencoded", login.Header("Content-Type"))
	assert.Equal(t, "user=alice&pass=p%26ss+word", string(login.Body()))

	upload := rrs["/upload"].Request()
	assert.Equal(t, "multipart/form-data; boundary="+defaultMultipartBoundary, upload.Header("Content-Type"))
	assert.Equal(t,
		"--"+defaultMultipartBoundary+"\r\n"+
			"Content-Disposition: form-data; name=\"title\"\r\n\r\n"+
			"hello\r\n"+
			"--"+defaultMultipartBoundary+"\r\n"+
			"Content-Disposition: form-data; name=\"doc\"; filename=\"report.pdf\"\r\n"+
			"Content-Type: application/octet-stream\r\n\r\n"+
			"\r\n"+
			"--"+defaultMultipartBoundary+"--\r\n",
		string(upload.Body()))
	assert.Equal(t, 1, strings.Count(string(upload.Raw()), "Content-Type: multipart"))

	imp := rrs["/import"].Request()
	assert.Equal(t, "application/xml", imp.Header("Content-Type"))
	assert.Equal(t, "<a>1</a>", string(imp.Body()))

	items := rrs["/items"].Request()
	assert.Equal(t, "application/json", items.Header("Content-Type"))

	gql := rrs["/graphql"].Request()
	assert.Equal(t, "application/json", gql.Header("Content-Type"))
	assert.JSONEq(t, `{"query":"query($id: ID!) { item(id: $id) { name } }","variables":{"id":"7"}}`, string(gql.Body()))
}

func TestFixture_UnresolvedVariablesWarnedOnce(t *testing.T) {
	rrs, f, logs := parseFixture(t, Options{})

	// Two requests with {{missingHost}} in the URL are skipped; the one with
	// {{traceId}} only in a header is kept with the placeholder.
	assert.NotContains(t, rrs, "/x")
	assert.NotContains(t, rrs, "/y")
	require.Contains(t, rrs, "/trace")
	assert.Equal(t, "{{traceId}}", rrs["/trace"].Request().Header("X-Trace"))

	st := f.Stats()
	assert.Equal(t, 2, st.Skipped)
	assert.Equal(t, VariableStats{Skipped: 2}, st.UnresolvedVariables["missingHost"])
	assert.Equal(t, VariableStats{Kept: 1}, st.UnresolvedVariables["traceId"])

	warns := logs.FilterLevelExact(zapcore.WarnLevel).All()
	require.Len(t, warns, 2, "one warning per unresolved variable")
	byVar := map[string]map[string]any{}
	for _, w := range warns {
		ctx := w.ContextMap()
		byVar[ctx["variable"].(string)] = ctx
	}
	assert.EqualValues(t, 2, byVar["missingHost"]["requests_skipped"])
	assert.EqualValues(t, 1, byVar["traceId"]["requests_kept_with_placeholder"])
}

func TestFixture_VariableSuppliedResolvesSkips(t *testing.T) {
	rrs, f, logs := parseFixture(t, Options{Variables: map[string]string{
		"missingHost": "http://other.example.test", "traceId": "t-1",
	}})
	assert.Contains(t, rrs, "/x")
	assert.Contains(t, rrs, "/y")
	assert.Equal(t, "t-1", rrs["/trace"].Request().Header("X-Trace"))
	assert.Zero(t, f.Stats().Skipped)
	assert.Empty(t, logs.FilterLevelExact(zapcore.WarnLevel).All())
}

func TestAuth_V20ObjectShape(t *testing.T) {
	data := []byte(`{
		"auth": {"type": "basic", "basic": {"username": "u", "password": "p"}},
		"item": [{"name": "a", "request": {"method": "GET", "url": "http://example.test/a"}}]
	}`)
	var got *httpmsg.HttpRequestResponse
	require.NoError(t, New().ParseFromData(data, func(rr *httpmsg.HttpRequestResponse) bool {
		got = rr
		return true
	}))
	require.NotNil(t, got)
	assert.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("u:p")), got.Request().Header("Authorization"))
}
