package smtp_header_injection

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestMain(m *testing.M) { modtest.VerifyNoLeaks(m) }

// fakeOAST returns a fixed host and records the params and payloads it was given.
type fakeOAST struct {
	host     string
	enabled  bool
	mu       sync.Mutex
	params   []string
	recorded []string
}

func (f *fakeOAST) GenerateURL(_, paramName, _, _, _ string) string {
	f.mu.Lock()
	f.params = append(f.params, paramName)
	f.mu.Unlock()
	return f.host
}
func (f *fakeOAST) RecordPayload(_, payload string) {
	f.mu.Lock()
	f.recorded = append(f.recorded, payload)
	f.mu.Unlock()
}
func (f *fakeOAST) Enabled() bool { return f.enabled }

func sink() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
}

// TestPlantsBccGraftForEmailParam: an email parameter gets the recipient probe and
// the Bcc-graft payloads, all embedding the unique collaborator host.
func TestPlantsBccGraftForEmailParam(t *testing.T) {
	srv := sink()
	defer srv.Close()

	const host = "abc123unique.oast.example"
	oast := &fakeOAST{host: host, enabled: true}

	rr := modtest.Request(t, srv.URL+"/contact?email=user@example.com")
	ip := modtest.InsertionPoint(t, rr, "email")

	res, err := New().ScanPerInsertionPoint(rr, ip, modtest.Requester(t), &modkit.ScanContext{OASTProvider: oast})
	require.NoError(t, err)
	require.Empty(t, res, "OAST confirmation is async; no synchronous findings")

	oast.mu.Lock()
	defer oast.mu.Unlock()
	require.NotEmpty(t, oast.recorded)
	var sawRecipient, sawBcc bool
	for _, p := range oast.recorded {
		require.Contains(t, p, host, "every planted payload must embed the collaborator host")
		if p == "vigolium-poc@"+host {
			sawRecipient = true
		}
		if strings.Contains(strings.ToLower(p), "bcc:") {
			sawBcc = true
		}
	}
	assert.True(t, sawRecipient, "a plain recipient (email-capability) payload must be planted")
	assert.True(t, sawBcc, "a Bcc-graft header-injection payload must be planted")
}

// TestNonEmailParamSkipped: a parameter that is neither email-named nor email-valued
// is not probed at all.
func TestNonEmailParamSkipped(t *testing.T) {
	srv := sink()
	defer srv.Close()

	oast := &fakeOAST{host: "h.oast.example", enabled: true}
	rr := modtest.Request(t, srv.URL+"/p?color=red")
	ip := modtest.InsertionPoint(t, rr, "color")

	_, err := New().ScanPerInsertionPoint(rr, ip, modtest.Requester(t), &modkit.ScanContext{OASTProvider: oast})
	require.NoError(t, err)

	oast.mu.Lock()
	defer oast.mu.Unlock()
	assert.Empty(t, oast.params, "a non-email parameter must not be probed")
}

// TestOASTDisabledNoop: with no collaborator there is no confirmation channel, so
// nothing is sent.
func TestOASTDisabledNoop(t *testing.T) {
	srv := sink()
	defer srv.Close()

	oast := &fakeOAST{host: "h", enabled: false}
	rr := modtest.Request(t, srv.URL+"/contact?email=user@example.com")
	ip := modtest.InsertionPoint(t, rr, "email")

	_, err := New().ScanPerInsertionPoint(rr, ip, modtest.Requester(t), &modkit.ScanContext{OASTProvider: oast})
	require.NoError(t, err)
	oast.mu.Lock()
	defer oast.mu.Unlock()
	assert.Empty(t, oast.params)
}

func TestIsEmailParam(t *testing.T) {
	t.Parallel()
	assert.True(t, isEmailParam("email", "x"))
	assert.True(t, isEmailParam("recipient_address", "x"))
	assert.True(t, isEmailParam("to", "x"))
	assert.True(t, isEmailParam("q", "user@example.com"), "email-shaped value qualifies")
	assert.False(t, isEmailParam("token", "abc"), "'token' must not match via the 'to' substring")
	assert.False(t, isEmailParam("color", "red"))
}
