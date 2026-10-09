package spring4shell_probe

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestMain(m *testing.M) { modtest.VerifyNoLeaks(m) }

// vulnerableBinder emulates a Spring @ModelAttribute handler on a vulnerable
// stack: the ClassLoader property binds true/false and fails conversion (400)
// for anything else; unknown parameters are ignored. seen records the values
// sent for the property, in order.
func vulnerableBinder(seen *[]string, mu *sync.Mutex) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Has(propertyPath) {
			v := q.Get(propertyPath)
			mu.Lock()
			*seen = append(*seen, v)
			mu.Unlock()
			if v != "true" && v != "false" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"status":400,"error":"Bad Request"}`))
				return
			}
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>greeting</body></html>"))
	}
}

func scan(t *testing.T, h http.Handler) []*output.ResultEvent {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	rr := modtest.Request(t, srv.URL+"/greeting?name=x")
	res, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	return res
}

func TestNew_Metadata(t *testing.T) {
	t.Parallel()
	m := New()
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, severity.High, m.Severity())
	assert.Equal(t, severity.Firm, m.Confidence())
	assert.Subset(t, m.Tags(), []string{"spring", "java", "moderate"})
	assert.Equal(t, modkit.ScanScopeRequest, m.ScanScopes())
}

// TestVulnerableBinder_Detected: the full true/non-boolean/false split,
// reproduced twice with a passing control, is reported.
func TestVulnerableBinder_Detected(t *testing.T) {
	t.Parallel()
	var seen []string
	var mu sync.Mutex
	res := scan(t, vulnerableBinder(&seen, &mu))
	require.Len(t, res, 1)

	f := res[0]
	assert.Equal(t, propertyPath, f.FuzzingParameter)
	assert.Equal(t, output.RecordKindFinding, f.RecordKind)
	assert.Contains(t, f.ExtractedResults, "status_nonbool=400")
	assert.Contains(t, f.ExtractedResults, "status_true=200")
	assert.Contains(t, f.ExtractedResults, "status_false=200")
	assert.Contains(t, f.Request, "class.module.classLoader.DefaultAssertionStatus=")
	assert.Contains(t, f.Response, "400")
	assert.NotEmpty(t, f.AdditionalEvidence)

	// Two rounds of nonbool, true, false; every "true" is followed by "false"
	// so the ClassLoader's assertion status is restored.
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, seen, 6)
	for i, v := range seen {
		if v == "true" {
			require.Less(t, i+1, len(seen))
			assert.Equal(t, "false", seen[i+1], "every true must be followed by a false reset")
		}
	}
	assert.Equal(t, "false", seen[len(seen)-1])
}

// TestPatched_NoFinding: a patched or non-Spring stack ignores the property,
// so the non-boolean value returns 200 and the probe stops after one request.
func TestPatched_NoFinding(t *testing.T) {
	t.Parallel()
	var hits int64
	res := scan(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		_, _ = w.Write([]byte("ok"))
	}))
	assert.Empty(t, res)
	assert.Equal(t, int64(1), atomic.LoadInt64(&hits), "a non-400 for the non-boolean value must end the probe")
}

// TestGeneric400OnUnknownParams_NoFinding: a strict API that rejects every
// parameter it does not know answers 400 to "true" as well.
func TestGeneric400OnUnknownParams_NoFinding(t *testing.T) {
	t.Parallel()
	res := scan(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k := range r.URL.Query() {
			if k != "name" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		_, _ = w.Write([]byte("ok"))
	}))
	assert.Empty(t, res)
}

// TestValueValidator_NoFinding: a server that answers 400 to any parameter
// whose value is not boolean-like, whatever its name, is caught by the
// random-name control.
func TestValueValidator_NoFinding(t *testing.T) {
	t.Parallel()
	res := scan(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, vs := range r.URL.Query() {
			if k == "name" {
				continue
			}
			for _, v := range vs {
				if v != "true" && v != "false" {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
			}
		}
		_, _ = w.Write([]byte("ok"))
	}))
	assert.Empty(t, res)
}

// TestFalseRejected_NoFinding: "false" must reach the handler like "true".
func TestFalseRejected_NoFinding(t *testing.T) {
	t.Parallel()
	res := scan(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if q := r.URL.Query(); q.Has(propertyPath) && q.Get(propertyPath) != "true" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	assert.Empty(t, res)
}

// TestNondeterministic_NoFinding: a split that does not reproduce in the
// second round (here the 400 was a one-off) is dropped.
func TestNondeterministic_NoFinding(t *testing.T) {
	t.Parallel()
	var nonBoolHits int64
	res := scan(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Has(propertyPath) {
			if v := q.Get(propertyPath); v != "true" && v != "false" {
				if atomic.AddInt64(&nonBoolHits, 1) == 1 {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
			}
		}
		_, _ = w.Write([]byte("ok"))
	}))
	assert.Empty(t, res)
}
