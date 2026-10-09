package text4shell_probe

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// Text4Shell confirmation is an out-of-band DNS/HTTP callback, which httptest
// cannot emulate; these tests cover the planting side (the payloads reach the
// parameter and are recorded against a fake OAST provider) and the no-OAST
// early return. The callback path is the OAST service's.

func TestMain(m *testing.M) { modtest.VerifyNoLeaks(m) }

type fakeOAST struct {
	mu       sync.Mutex
	types    []string
	recorded []string
}

func (f *fakeOAST) GenerateURL(_, _, injectionType, _, _ string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.types = append(f.types, injectionType)
	return "t4s.oast.test"
}

func (f *fakeOAST) RecordPayload(_, payload string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recorded = append(f.recorded, payload)
}

func (f *fakeOAST) Enabled() bool { return true }

// recorder captures the q values the server receives.
func recorder(seen *[]string, mu *sync.Mutex) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*seen = append(*seen, r.URL.Query().Get("q"))
		mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	}))
}

func TestNew_Metadata(t *testing.T) {
	t.Parallel()
	m := New()
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, severity.Critical, m.Severity())
	assert.Subset(t, m.Tags(), []string{"java", "rce", "moderate"})
	assert.Equal(t, modkit.ScanScopeInsertionPoint, m.ScanScopes())
}

// TestPlantsLookups: both out-of-band lookups reach the parameter verbatim and
// are recorded so a callback reconstructs the real payload. The script lookup
// is never sent.
func TestPlantsLookups(t *testing.T) {
	t.Parallel()
	var seen []string
	var mu sync.Mutex
	srv := recorder(&seen, &mu)
	defer srv.Close()

	oast := &fakeOAST{}
	rr := modtest.Request(t, srv.URL+"/render?q=hello")
	res, err := New().ScanPerInsertionPoint(rr, modtest.InsertionPoint(t, rr, "q"), modtest.Requester(t), &modkit.ScanContext{OASTProvider: oast})
	require.NoError(t, err)
	assert.Empty(t, res, "findings arrive asynchronously via OAST")

	want := []string{"${dns:t4s.oast.test}", "${url:UTF-8:http://t4s.oast.test/}"}
	mu.Lock()
	assert.ElementsMatch(t, want, seen)
	mu.Unlock()

	oast.mu.Lock()
	defer oast.mu.Unlock()
	assert.ElementsMatch(t, want, oast.recorded)
	for _, p := range oast.recorded {
		assert.NotContains(t, p, "script:")
	}
	for _, typ := range oast.types {
		assert.NotContains(t, strings.ToLower(typ), "header", "a header label would mis-route the OAST classifier")
	}
}

// TestNoOAST_NoRequests: without an OAST provider nothing can confirm the
// lookup, so nothing is sent.
func TestNoOAST_NoRequests(t *testing.T) {
	t.Parallel()
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
	}))
	defer srv.Close()

	rr := modtest.Request(t, srv.URL+"/render?q=hello")
	res, err := New().ScanPerInsertionPoint(rr, modtest.InsertionPoint(t, rr, "q"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res)
	assert.Equal(t, int64(0), atomic.LoadInt64(&hits))
}
