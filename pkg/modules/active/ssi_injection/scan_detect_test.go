package ssi_injection

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestMain(m *testing.M) { modtest.VerifyNoLeaks(m) }

// ssiComment matches any SSI-style comment, so a test server can emulate a parser by
// replacing it. The captured group is the directive body.
var ssiComment = regexp.MustCompile(`<!--#([^>]*?)-->`)

const testDateGMT = "Sunday, 21-Sep-2026 12:00:00 GMT"

// renderSSI emulates an SSI-enabled document: it evaluates `#echo var="DATE_GMT"` to a
// date and leaves any ordinary comment (no leading "#") untouched, exactly as a real
// parser does.
func renderSSI(in string) string {
	return ssiComment.ReplaceAllStringFunc(in, func(m string) string {
		if strings.Contains(m, "DATE_GMT") {
			return testDateGMT
		}
		return "[an error occurred while processing this directive]"
	})
}

func htmlPage(body string) string { return "<html><body>result: " + body + "</body></html>" }

// scanQ runs the module against a one-handler server with the payload in ?q=.
func scanQ(t *testing.T, h http.HandlerFunc) []*output.ResultEvent {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	rr := modtest.Request(t, srv.URL+"/page.shtml?q=hello")
	res, err := New().ScanPerInsertionPoint(rr, modtest.InsertionPoint(t, rr, "q"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	return res
}

func htmlHandler(render func(q string) string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(render(r.URL.Query().Get("q"))))
	}
}

// ssiPage serves a document whose SSI comments the server genuinely parses.
func ssiPage() http.HandlerFunc {
	return htmlHandler(func(q string) string { return htmlPage(renderSSI(q)) })
}

// evaluatingStatus serves a genuinely SSI-evaluated page under a given Server header
// and status, so provenance — not the body — must decide the verdict.
func evaluatingStatus(server string, status int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if server != "" {
			w.Header().Set("Server", server)
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(htmlPage(renderSSI(r.URL.Query().Get("q")))))
	}
}

// stripComments replaces every HTML comment with `with` — the sanitizer class the
// control round exists to catch.
func stripComments(with string) http.HandlerFunc {
	re := regexp.MustCompile(`<!--.*?-->`)
	return htmlHandler(func(q string) string { return htmlPage(re.ReplaceAllString(q, with)) })
}

// scanCountingRequests runs scanQ against h and reports how many requests it drew.
func scanCountingRequests(t *testing.T, h http.HandlerFunc) ([]*output.ResultEvent, int64) {
	t.Helper()
	var hits atomic.Int64
	res := scanQ(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1); h(w, r) })
	return res, hits.Load()
}

// TestScanPerInsertionPoint_DetectsSSI: the server parses the comment, so the tags come
// back around a server-owned date — a confirmed SSI injection, reported with that value.
func TestScanPerInsertionPoint_DetectsSSI(t *testing.T) {
	t.Parallel()
	res := scanQ(t, ssiPage())
	require.NotEmpty(t, res, "an SSI-evaluating endpoint must be reported")
	assert.Equal(t, ModuleName, res[0].Info.Name)
	assert.Equal(t, "q", res[0].FuzzingParameter)
	assert.Contains(t, res[0].ExtractedResults, "server_value="+testDateGMT,
		"the finding must carry the server-owned value it proved")
}

// TestScanPerInsertionPoint_UndefinedVariableStillProves: the proof is that the parser
// consumed the comment, not that DATE_GMT resolved — so Apache's "(none)" and nginx's
// "none" fallbacks must still confirm. This is what keeps the check portable.
func TestScanPerInsertionPoint_UndefinedVariableStillProves(t *testing.T) {
	t.Parallel()
	for _, fallback := range []string{"(none)", "none", "[an error occurred while processing this directive]"} {
		t.Run(fallback, func(t *testing.T) {
			t.Parallel()
			res := scanQ(t, htmlHandler(func(q string) string {
				return htmlPage(ssiComment.ReplaceAllString(q, fallback))
			}))
			assert.NotEmpty(t, res, "a parsed comment must confirm even when the variable does not resolve")
		})
	}
}

// akamaiEscape mimics the Akamai "Access Denied" page's rendering of the requested
// URL: every non-alphanumeric byte becomes a numeric character reference. That is what
// hid the old oracle's directive tokens while leaving its alphanumeric canary readable.
func akamaiEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			b.WriteByte(c)
			continue
		}
		b.WriteString("&#")
		b.WriteString(strconv.Itoa(int(c)))
		b.WriteByte(';')
	}
	return b.String()
}

// akamaiDenial is the edge block that produced the bulk of this module's false
// positives: a 403 from AkamaiGHost whose HTML body echoes the requested URL with
// every non-alphanumeric byte entity-escaped.
func akamaiDenial(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "AkamaiGHost")
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusForbidden)
	_, _ = fmt.Fprintf(w, "<HTML><HEAD>\n<TITLE>Access Denied</TITLE>\n</HEAD><BODY>\n"+
		"<H1>Access Denied</H1>\nYou don't have permission to access \"%s\" on this server.<P>\n"+
		"</BODY>\n</HTML>\n", akamaiEscape(r.URL.RequestURI()))
}

// TestScanPerInsertionPoint_Rejections covers every response that must NOT be reported
// as SSI. The first four reproduce findings this module actually filed against real
// targets; the rest are the neighbouring shapes the oracle would otherwise accept.
func TestScanPerInsertionPoint_Rejections(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		// plannerrequest.hyatt.com, book.beachbound.com, mfa.qabmo.gs.com
		{"akamai 403 echoing the URL", akamaiDenial},
		// marquee-qa.gs.com: the login page embeds the original URL in an OAuth
		// `state`, percent-encoding an already percent-encoded path ("%23" -> "%2523").
		{"sso 401 interstitial with the URL in an OAuth state", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "webserver")
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprintf(w, `<html><head><meta name="robots" content="noindex"></head><body>`+
				`<input type="hidden" id="login-url" value="https://idp.example.com/as/authorization.oauth2?state=%s" />`+
				`</body></html>`, url.QueryEscape(r.URL.RequestURI()))
		}},
		// Provenance must decide these three, whatever the body shows.
		{"akamai 403 whose body looks evaluated", evaluatingStatus("AkamaiGHost", http.StatusForbidden)},
		{"401 auth gate whose body looks evaluated", evaluatingStatus("webserver", http.StatusUnauthorized)},
		{"404 catch-all that evaluates", evaluatingStatus("", http.StatusNotFound)},

		{"verbatim reflection", htmlHandler(htmlPage)},
		{"entity-escaped reflection on a 200", htmlHandler(func(q string) string { return htmlPage(akamaiEscape(q)) })},
		{"double-percent-encoded reflection on a 200", htmlHandler(func(q string) string { return htmlPage(url.QueryEscape(q)) })},

		// The class the previous absence-based oracle could not see: nothing is
		// escaped, the directive keywords are simply deleted.
		{"keyword-stripping WAF", htmlHandler(func(q string) string {
			return htmlPage(strings.NewReplacer("#echo", "", "#set", "", "#include", "", "#exec", "").Replace(q))
		})},
		// The class this design introduces. The first two are caught by the needle
		// alone — an empty middle fails the >= 1 bound, and a single space is itself a
		// subsequence of the directive — but a sanitizer that substitutes arbitrary
		// text leaves a middle that looks exactly like a server value, and only the
		// control round rules it out.
		{"comment-stripping sanitizer", stripComments("")},
		{"comment-stripping sanitizer leaving a space", stripComments(" ")},
		{"comment-substituting sanitizer", stripComments("[removed]")},
		// Stripped to alphanumerics the middle is plain by byte, so only its being a
		// subsequence of the directive gives it away.
		{"punctuation-stripping reflection", htmlHandler(func(q string) string {
			var b strings.Builder
			for i := 0; i < len(q); i++ {
				if c := q[i]; (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
					b.WriteByte(c)
				}
			}
			return htmlPage(b.String())
		})},
		// ...and the same, lowercased, which a word blocklist would have missed.
		{"punctuation-stripping reflection, lowercased", htmlHandler(func(q string) string {
			var b strings.Builder
			for i := 0; i < len(q); i++ {
				if c := q[i]; (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
					b.WriteByte(c)
				}
			}
			return htmlPage(strings.ToLower(b.String()))
		})},

		{"non-HTML response that evaluates", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"result":"` + renderSSI(r.URL.Query().Get("q")) + `"}`))
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Empty(t, scanQ(t, tc.handler), "must not be reported as SSI")
		})
	}
}

// TestScanPerInsertionPoint_EdgeBlockStopsProbing: the provenance gate runs before
// `reached` is set, so a denied path costs one request and draws neither a control
// round nor out-of-band exec probes.
func TestScanPerInsertionPoint_EdgeBlockStopsProbing(t *testing.T) {
	t.Parallel()
	res, hits := scanCountingRequests(t, akamaiDenial)
	assert.Empty(t, res)
	assert.Equal(t, int64(1), hits, "a blocked first response must not be followed by more probes")
}

// TestScanPerInsertionPoint_ControlIsSent: a confirmation costs exactly two requests —
// the probe and the control that rules out a comment stripper.
func TestScanPerInsertionPoint_ControlIsSent(t *testing.T) {
	t.Parallel()
	res, hits := scanCountingRequests(t, ssiPage())
	require.NotEmpty(t, res)
	assert.Equal(t, int64(2), hits, "a confirmation is one probe plus one control")
}

// TestSSIEchoValue exercises the needle directly. want == "" means "must not match";
// ssiEchoValue never returns an empty value for a match, since the middle must be >= 1
// byte.
func TestSSIEchoValue(t *testing.T) {
	t.Parallel()
	const l, r = "vgoaaaaaaaaaa", "vgobbbbbbbbbb"

	tests := []struct {
		name, middle, want string
	}{
		{"a plain server value is an evaluation", testDateGMT, testDateGMT},
		{"apache undefined-variable fallback", "(none)", "(none)"},
		{"apache directive error", "[an error occurred while processing this directive]",
			"[an error occurred while processing this directive]"},
		{`verbatim reflection keeps "<"`, ssiEchoDirective, ""},
		{`entity-escaped reflection keeps "&"`, akamaiEscape(ssiEchoDirective), ""},
		{`percent-encoded reflection keeps "%"`, url.QueryEscape(ssiEchoDirective), ""},
		{"an empty middle is a stripped comment", "", ""},
		{"an over-long middle is an unrelated tag pair", strings.Repeat("a", ssiMiddleMax+1), ""},
		{"the directive's own words are not a server value", "echovarDATEGMT", ""},
		{"...nor are they lowercased", "echovardategmt", ""},
		{"...nor a shorter fragment of them", "varDATE", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := ssiEchoValue("page "+l+tc.middle+r+" more", l, r)
			if tc.want == "" {
				assert.False(t, ok, "must not match")
				return
			}
			assert.True(t, ok, "must match")
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestSSIEchoValue_LaterOccurrence: the first tag pair is a reflection, the second a
// real evaluation — the scan must not stop at the first.
func TestSSIEchoValue_LaterOccurrence(t *testing.T) {
	t.Parallel()
	const l, r = "vgoaaaaaaaaaa", "vgobbbbbbbbbb"
	got, ok := ssiEchoValue(l+ssiEchoDirective+r+" ... "+l+testDateGMT+r, l, r)
	require.True(t, ok)
	assert.Equal(t, testDateGMT, got)
}

// TestSSIEchoValue_TruncatedTagsAreBounded: a page that reflects the input into many
// truncated slots keeps the left tag but drops the right. The right-tag search is
// bounded to ssiMiddleMax so this stays linear; unbounded it was quadratic (8.5s on a
// ~900 KB body).
func TestSSIEchoValue_TruncatedTagsAreBounded(t *testing.T) {
	t.Parallel()
	const l, r = "vgoaaaaaaaaaa", "vgobbbbbbbbbb"
	var b strings.Builder
	for range 50000 {
		b.WriteString(l + "truncated ")
	}
	// One right tag at the very end, further than ssiMiddleMax from the last left tag,
	// so nothing matches and every occurrence would scan to here if unbounded.
	b.WriteString(strings.Repeat("x", ssiMiddleMax+1) + r)

	done := make(chan bool, 1)
	go func() {
		_, ok := ssiEchoValue(b.String(), l, r)
		done <- ok
	}()
	select {
	case ok := <-done:
		assert.False(t, ok, "truncated reflections carry no valid middle")
	case <-time.After(5 * time.Second):
		t.Fatal("ssiEchoValue did not finish: the right-tag search is unbounded again")
	}
}
