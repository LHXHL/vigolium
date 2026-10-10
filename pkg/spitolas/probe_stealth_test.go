//go:build integration

package spitolas

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestProbeURLStealth: module confirmations go through ProbeURL, which must
// present the same browser the crawl does (stealth auto → on for chromium).
func TestProbeURLStealth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body><pre id="out"></pre><script>
document.getElementById('out').textContent = 'webdriver=' + navigator.webdriver +
  ' plugins=' + navigator.plugins.length +
  ' brands=' + (navigator.userAgentData ? navigator.userAgentData.brands.map(b => b.brand).join('|') : 'none');
</script></body></html>`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := ProbeURL(ctx, ProbeConfig{URL: srv.URL, CollectHTML: true, NavTimeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("ProbeURL: %v", err)
	}
	if !strings.Contains(res.HTML, "webdriver=false") {
		t.Errorf("probe page saw navigator.webdriver != false: %s", res.HTML)
	}
	if strings.Contains(res.HTML, "plugins=0") {
		t.Errorf("probe page saw no plugins: %s", res.HTML)
	}
	if strings.Contains(res.HTML, "Headless") || !strings.Contains(res.HTML, "Google Chrome") {
		t.Errorf("probe page brands: %s", res.HTML)
	}
}
