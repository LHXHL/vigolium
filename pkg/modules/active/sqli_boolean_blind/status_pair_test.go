package sqli_boolean_blind

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// statusOracleHandler is a boolean sink whose FALSE branch is expressed as a
// status: the row-found page is a 200, a missing row is a 404, and a SQL syntax
// error is a 500 (a malformed expression, or the unbalanced `'")` control).
func statusOracleHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		if strings.HasSuffix(v, syntaxBreakSuffix) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprint(w, errorPage)
			return
		}
		switch page := evalBool(v); page {
		case truePage:
			_, _ = fmt.Fprint(w, truePage)
		case falsePage:
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, falsePage)
		default:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprint(w, page)
		}
	}
}

// TestScanPerRequest_StatusOracle_Detected: a 200/200/404 split that follows
// boolean truth across random operands, reproduces, and is distinct from the
// syntax-error status is reported at Firm with the statuses in the evidence.
func TestScanPerRequest_StatusOracle_Detected(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(statusOracleHandler())
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/item?id=1"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a reproducible 200/200/404 boolean status oracle must be reported")
	f := res[0]
	assert.Equal(t, "id", f.FuzzingParameter)
	assert.Equal(t, severity.Firm, f.Info.Confidence, "a status oracle is Firm, never Certain")
	assert.Equal(t, "status-oracle", f.Metadata["differential"])
	assert.Contains(t, f.Info.Description, "TRUE=200 FALSE=404 syntax-break=500")
	assert.Contains(t, strings.Join(f.AdditionalEvidence, "\n"), "# [status-oracle] baseline=200 TRUE=200 FALSE=404 syntax-break=500")
}

// TestScanPerRequest_StatusOracle_NonNumeric404 is a numeric route that returns
// 404 for anything that is not an integer. Every payload is non-numeric, so TRUE
// already leaves the baseline status and nothing may be reported.
func TestScanPerRequest_StatusOracle_NonNumeric404(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		for _, c := range v {
			if c < '0' || c > '9' {
				w.WriteHeader(http.StatusNotFound)
				_, _ = fmt.Fprint(w, falsePage)
				return
			}
		}
		_, _ = fmt.Fprint(w, truePage)
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/item?id=1"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a route that 404s every non-numeric value must not be reported")
}

// TestScanPerRequest_StatusOracle_SyntaxBreakControl: the TRUE/FALSE split is
// real and survives random operands, but malformed input lands on the same 404
// as FALSE. The flip is then indistinguishable from input validation, so the
// syntax-break control must reject it — and must actually have been sent.
func TestScanPerRequest_StatusOracle_SyntaxBreakControl(t *testing.T) {
	t.Parallel()
	var controlHits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		if strings.HasSuffix(v, syntaxBreakSuffix) {
			atomic.AddInt64(&controlHits, 1)
		}
		if strings.HasSuffix(v, syntaxBreakSuffix) || invalidRe.MatchString(v) || evalBool(v) == falsePage {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, falsePage)
			return
		}
		_, _ = fmt.Fprint(w, truePage)
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/item?id=1"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a FALSE status that malformed input also produces must not be reported")
	assert.Positive(t, atomic.LoadInt64(&controlHits), "the syntax-break control must have been probed")
}

// TestScanPerRequest_StatusOracle_LiteralToken: a 404 bound to the literal `1=2`
// token (a filter, not SQL) classifies as a status oracle on the curated pair,
// but random operands make both branches 200, so confirmation rejects it.
func TestScanPerRequest_StatusOracle_LiteralToken(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("id"), "1=2") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, falsePage)
			return
		}
		_, _ = fmt.Fprint(w, truePage)
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/item?id=1"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a status flip bound to the literal 1=2 token must not be reported")
}

// TestScanPerRequest_StatusOracle_LoginRedirect: FALSE redirecting to a login
// page is an auth artifact, never an oracle (the 302→/login regression in
// TestScanPerRequest_NoFalsePositive_StatusFlip, here with a 500 syntax error
// so only the login-redirect rule can reject it).
func TestScanPerRequest_StatusOracle_LoginRedirect(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		switch {
		case strings.HasSuffix(v, syntaxBreakSuffix) || invalidRe.MatchString(v):
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprint(w, errorPage)
		case evalBool(v) == falsePage:
			http.Redirect(w, r, "/login?next=/item", http.StatusFound)
		default:
			_, _ = fmt.Fprint(w, truePage)
		}
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/item?id=1"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a FALSE branch that redirects to login must not be reported")
}

// TestScanPerRequest_SameStatusNon200 covers stable non-200 triplets: a boolean
// sink served entirely as 201 (or as 404 pages with a body) goes through the
// unchanged content-differential steps and is reported at the module's default
// confidence.
func TestScanPerRequest_SameStatusNon200(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusCreated, http.StatusNotFound} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				_, _ = fmt.Fprint(w, evalBool(r.URL.Query().Get("id")))
			}))
			defer srv.Close()

			res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/item?id=1"), modtest.Requester(t), &modkit.ScanContext{})
			require.NoError(t, err)
			require.NotEmpty(t, res, "a %d-triplet content differential must be reported", status)
			assert.Equal(t, "id", res[0].FuzzingParameter)
			assert.Empty(t, res[0].Info.Confidence, "a content differential keeps the module default confidence")
			assert.Nil(t, res[0].Metadata["differential"])
		})
	}
}
