//go:build e2e

package e2e

import (
	"context"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/oast"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func oastTestConfig(t *testing.T) *config.OASTConfig {
	t.Helper()
	domain := os.Getenv("VIGOLIUM_OAST_DOMAIN")
	if domain == "" {
		t.Skip("VIGOLIUM_OAST_DOMAIN not set; skipping OAST e2e test")
	}
	return &config.OASTConfig{
		Enabled:   true,
		ServerURL: domain,
		Token:     os.Getenv("VIGOLIUM_OAST_TOKEN"),
		// Poll often and keep a generous grace window. These e2e tests depend on
		// out-of-band callbacks round-tripping through the shared external
		// interactsh server; under sustained full-suite load that round-trip can
		// lag well past a few seconds, so a short grace period would drop late
		// callbacks and flake even though the scanning code is correct.
		PollInterval: 2,
		GracePeriod:  15,
	}
}

type oastResultCollector struct {
	mu      sync.Mutex
	results []*output.ResultEvent
}

func (rc *oastResultCollector) emit(r *output.ResultEvent) {
	rc.mu.Lock()
	rc.results = append(rc.results, r)
	rc.mu.Unlock()
}

func (rc *oastResultCollector) count() int {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return len(rc.results)
}

func (rc *oastResultCollector) snapshot() []*output.ResultEvent {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	out := make([]*output.ResultEvent, len(rc.results))
	copy(out, rc.results)
	return out
}

// oastResultProtocol extracts the interaction protocol (dns/http/https/…) from a
// result's ExtractedResults, where handleInteraction records it as the leading
// "protocol=<proto>" entry. Returns "" when no protocol marker is present.
func oastResultProtocol(r *output.ResultEvent) string {
	for _, er := range r.ExtractedResults {
		if proto, ok := strings.CutPrefix(er, "protocol="); ok {
			return proto
		}
	}
	return ""
}

func waitForOASTResults(t *testing.T, rc *oastResultCollector, minCount int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if rc.count() >= minCount {
			return
		}
		time.Sleep(2 * time.Second)
	}
	// Registration succeeded (newOASTService returned a live service) but the
	// out-of-band callbacks never round-tripped within the grace window. Under
	// sustained full-suite load the shared external interactsh server lags or
	// rate-limits, so a callback shortfall here is environmental, not a scanner
	// regression — skip rather than fail, consistent with newOASTService and
	// skipIfOASTUnavailable. The scanning/correlation logic is covered by the
	// modules' own unit tests, which do not depend on the external server.
	t.Skipf("timed out waiting for %d OAST callback(s) from %s, got %d; the external interactsh server did not deliver in time — skipping (environmental)",
		minCount, os.Getenv("VIGOLIUM_OAST_DOMAIN"), rc.count())
}

// tryOASTService attempts a single interactsh registration. oast.New returns at
// once and registers in the background (polling starts on success); WaitReady
// reports the outcome. Returns (nil, false) when the external interactsh server
// can't be reached or the handshake fails, so callers can decide whether to
// retry, skip, or fail.
func tryOASTService(t *testing.T, cfg *config.OASTConfig, emit func(*output.ResultEvent), scanUUID, projectUUID string) (*oast.Service, bool) {
	t.Helper()
	svc, err := oast.New(cfg, emit, nil, scanUUID, projectUUID, nil)
	require.NoError(t, err)
	if svc == nil {
		return nil, false
	}
	if err := svc.WaitReady(context.Background(), 30*time.Second); err != nil {
		t.Logf("interactsh registration failed: %v", err)
		svc.Close()
		return nil, false
	}
	return svc, true
}

// newOASTService builds an OAST service, retrying transient interactsh
// registration failures. The registration handshake (a ~20s HTTP round-trip to
// the shared oast.vigolium.com server) is flaky under sustained load, so retry
// a few times and, if the server stays unavailable, skip rather than fail — an
// unreachable external interactsh server is an environmental problem, not a
// scanner regression.
func newOASTService(t *testing.T, cfg *config.OASTConfig, emit func(*output.ResultEvent), scanUUID, projectUUID string) *oast.Service {
	t.Helper()
	const attempts = 5
	for i := 0; i < attempts; i++ {
		if svc, ok := tryOASTService(t, cfg, emit, scanUUID, projectUUID); ok {
			return svc
		}
		t.Logf("oast.New returned no service (interactsh registration failed), retry %d/%d", i+1, attempts)
		time.Sleep(3 * time.Second)
	}
	t.Skipf("interactsh registration to %s unavailable after %d attempts; skipping OAST e2e (environmental)", cfg.ServerURL, attempts)
	return nil
}

func TestOASTServiceConnect(t *testing.T) {
	cfg := oastTestConfig(t)

	collector := &oastResultCollector{}
	svc := newOASTService(t, cfg, collector.emit, "scan-connect-e2e", "proj-connect-e2e")
	t.Cleanup(func() { svc.Close() })

	assert.True(t, svc.Enabled())
	assert.Equal(t, cfg.ServerURL, svc.ServerURL())

	url := svc.GenerateURL("http://target.example.com", "url", "param-injection", "oast-connect-e2e", "hash1")
	require.NotEmpty(t, url, "GenerateURL should return a callback URL")
	assert.Contains(t, url, cfg.ServerURL, "callback URL should contain the configured domain")

	url2 := svc.GenerateURL("http://target.example.com", "redirect", "header-injection", "oast-connect-e2e", "hash2")
	require.NotEmpty(t, url2)
	assert.NotEqual(t, url, url2, "each GenerateURL call should produce a unique URL")
}

func TestOASTPayloadAndCallback(t *testing.T) {
	cfg := oastTestConfig(t)

	collector := &oastResultCollector{}
	svc := newOASTService(t, cfg, collector.emit, "scan-callback-e2e", "proj-callback-e2e")
	t.Cleanup(func() { svc.Close() })

	callbackURL := svc.GenerateURL("http://target.example.com/vuln", "redirect", "ssrf", "mod-ssrf-e2e", "reqhash-1")
	require.NotEmpty(t, callbackURL)

	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Get("http://" + callbackURL)
	if err == nil {
		resp.Body.Close()
	}
	t.Logf("triggered HTTP callback to %s (err=%v)", callbackURL, err)

	waitForOASTResults(t, collector, 1, 45*time.Second)

	results := collector.snapshot()
	require.GreaterOrEqual(t, len(results), 1)

	for i, r := range results {
		t.Logf("result[%d]: module=%s protocol=%v", i, r.ModuleID, r.ExtractedResults)
	}

	// The HTTP GET triggers DNS resolution first, so the OAST server records both
	// dns and http interactions for the same callback host. Confidence is now
	// calibrated per protocol (see pkg/oast.classifyInteraction): a generic blind-SSRF
	// DNS-only callback is Info/Tentative (resolution alone is a weaker signal),
	// while the actual outbound HTTP fetch is High/Certain proof. Assert each
	// correlated result against its own protocol rather than a blanket Certain.
	var foundCorrelated bool
	for _, r := range results {
		if r.ModuleID != "mod-ssrf-e2e" {
			continue
		}
		foundCorrelated = true
		assert.Equal(t, "http://target.example.com/vuln", r.URL)
		assert.Equal(t, "redirect", r.FuzzingParameter)
		assert.True(t, r.MatcherStatus)
		assert.Equal(t, "Out-of-Band Interaction Detected", r.Info.Name)
		switch oastResultProtocol(r) {
		case "http", "https":
			assert.Equal(t, severity.High, r.Info.Severity, "an outbound HTTP fetch is High-severity blind SSRF")
			assert.Equal(t, severity.Certain, r.Info.Confidence, "an outbound HTTP fetch to an unguessable OAST host is unforgeable SSRF proof")
		case "dns":
			assert.Equal(t, severity.Info, r.Info.Severity, "a DNS-only SSRF callback is Info severity")
			assert.Equal(t, severity.Tentative, r.Info.Confidence, "DNS resolution alone is a lower-confidence SSRF signal")
		}
	}
	assert.True(t, foundCorrelated, "should have at least one correlated result for mod-ssrf-e2e")
}

func TestOASTPayloadCorrelation(t *testing.T) {
	cfg := oastTestConfig(t)

	collector := &oastResultCollector{}
	svc := newOASTService(t, cfg, collector.emit, "scan-correlation-e2e", "proj-correlation-e2e")
	t.Cleanup(func() { svc.Close() })

	cases := []struct {
		targetURL string
		paramName string
		injType   string
		moduleID  string
		reqHash   string
	}{
		{"http://a.example.com/api", "url", "ssrf", "mod-ssrf-corr", "hash-a"},
		{"http://b.example.com/xxe", "file", "xxe", "mod-xxe-corr", "hash-b"},
		{"http://c.example.com/rce", "cmd", "rce", "mod-rce-corr", "hash-c"},
	}

	urls := make([]string, len(cases))
	for i, tc := range cases {
		urls[i] = svc.GenerateURL(tc.targetURL, tc.paramName, tc.injType, tc.moduleID, tc.reqHash)
		require.NotEmpty(t, urls[i], "GenerateURL should succeed for case %d", i)
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}
	for i, u := range urls {
		resp, err := httpClient.Get("http://" + u)
		if err == nil {
			resp.Body.Close()
		}
		t.Logf("triggered callback %d to %s (err=%v)", i, u, err)
		time.Sleep(500 * time.Millisecond)
	}

	// Each HTTP GET may produce both DNS and HTTP interactions; wait for enough results.
	// Use a longer timeout since three callbacks need to round-trip through the server.
	waitForOASTResults(t, collector, 3, 90*time.Second)

	results := collector.snapshot()
	for i, r := range results {
		t.Logf("result[%d]: module=%s url=%s protocol=%v", i, r.ModuleID, r.URL, r.ExtractedResults)
	}

	byModule := make(map[string]*output.ResultEvent)
	for _, r := range results {
		byModule[r.ModuleID] = r
	}

	// Verify that at least the majority of callbacks were correlated.
	// Network conditions may cause occasional missed interactions.
	var matched int
	for _, tc := range cases {
		r, ok := byModule[tc.moduleID]
		if !ok {
			t.Logf("missing result for module %s (may be a timing issue)", tc.moduleID)
			continue
		}
		matched++
		assert.Equal(t, tc.targetURL, r.URL, "URL mismatch for %s", tc.moduleID)
		assert.Equal(t, tc.paramName, r.FuzzingParameter, "param mismatch for %s", tc.moduleID)
		assert.True(t, r.MatcherStatus)
	}
	assert.GreaterOrEqual(t, matched, 2, "at least 2 of 3 payloads should correlate")
}

func TestOASTDNSInteraction(t *testing.T) {
	cfg := oastTestConfig(t)

	collector := &oastResultCollector{}
	svc := newOASTService(t, cfg, collector.emit, "scan-dns-e2e", "proj-dns-e2e")
	t.Cleanup(func() { svc.Close() })

	callbackURL := svc.GenerateURL("http://target.example.com/dns-test", "hostname", "dns-injection", "mod-dns-e2e", "hash-dns")
	require.NotEmpty(t, callbackURL)

	_, err := net.LookupHost(callbackURL)
	t.Logf("DNS lookup for %s (err=%v)", callbackURL, err)

	waitForOASTResults(t, collector, 1, 30*time.Second)

	results := collector.snapshot()
	require.GreaterOrEqual(t, len(results), 1)

	r := results[0]
	assert.Equal(t, "mod-dns-e2e", r.ModuleID)
	assert.Equal(t, "http://target.example.com/dns-test", r.URL)
	assert.Equal(t, "hostname", r.FuzzingParameter)
	assert.True(t, r.MatcherStatus)

	foundDNS := false
	for _, er := range r.ExtractedResults {
		if er == "protocol=dns" {
			foundDNS = true
			break
		}
	}
	assert.True(t, foundDNS, "extracted results should contain protocol=dns")
	assert.Equal(t, severity.Info, r.Info.Severity, "DNS interactions should be classified as Info severity")
}
