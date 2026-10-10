//go:build integration

package browser

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// stealthReportPage records, from an inline page script (so after any init
// script and before anything the crawler evaluates), what a bot wall would read.
const stealthReportPage = `<!doctype html><html><body><pre id="out"></pre><script>
  const ua = navigator.userAgentData;
  document.getElementById('out').textContent = JSON.stringify({
    webdriver: navigator.webdriver,
    webdriverOwn: Object.prototype.hasOwnProperty.call(navigator, 'webdriver'),
    plugins: navigator.plugins.length,
    pluginsIsArray: navigator.plugins instanceof PluginArray,
    mimeTypes: navigator.mimeTypes.length,
    languages: Array.from(navigator.languages),
    brands: ua ? ua.brands.map((b) => b.brand) : null,
    userAgent: navigator.userAgent,
    getterNative: (() => { try {
      const d = Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver');
      return Function.prototype.toString.call(d.get).includes('[native code]');
    } catch (e) { return false; } })(),
  });
</script></body></html>`

type stealthReport struct {
	Webdriver      bool     `json:"webdriver"`
	WebdriverOwn   bool     `json:"webdriverOwn"`
	Plugins        int      `json:"plugins"`
	PluginsIsArray bool     `json:"pluginsIsArray"`
	MimeTypes      int      `json:"mimeTypes"`
	Languages      []string `json:"languages"`
	Brands         []string `json:"brands"`
	UserAgent      string   `json:"userAgent"`
	GetterNative   bool     `json:"getterNative"`
}

// loadStealthReport launches a browser under stealth mode, loads the report
// page from a local server and returns what the page saw plus the Sec-CH-UA
// header the navigation carried.
func loadStealthReport(t *testing.T, stealth string) (stealthReport, string) {
	t.Helper()
	rep, secCHUA, _ := loadStealthPage(t, stealth)
	return rep, secCHUA
}

func loadStealthPage(t *testing.T, stealth string) (stealthReport, string, *Page) {
	t.Helper()
	var mu sync.Mutex
	secCHUA := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if v := r.Header.Get("Sec-CH-UA"); v != "" {
			secCHUA = v
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(stealthReportPage))
	}))
	t.Cleanup(server.Close)

	cfg, err := config.New(server.URL)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	cfg.Headless = true
	cfg.Stealth = stealth
	b, err := New(cfg)
	if err != nil {
		t.Fatalf("browser: %v", err)
	}
	t.Cleanup(func() { b.Close() })
	p, err := b.NewPage()
	if err != nil {
		t.Fatalf("page: %v", err)
	}
	if err := p.Navigate(server.URL); err != nil {
		t.Fatalf("navigate: %v", err)
	}
	out, err := p.rodPage.Eval(`() => document.getElementById('out').textContent`)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var rep stealthReport
	if err := json.Unmarshal([]byte(out.Value.Str()), &rep); err != nil {
		t.Fatalf("decode report %q: %v", out.Value.Str(), err)
	}
	mu.Lock()
	defer mu.Unlock()
	return rep, secCHUA, p
}

func TestStealthPatchesAutomationMarkers(t *testing.T) {
	rep, secCHUA, p := loadStealthPage(t, config.StealthAuto)
	t.Logf("report: %+v; Sec-CH-UA: %q", rep, secCHUA)

	if rep.Webdriver {
		t.Error("navigator.webdriver is true under stealth")
	}
	if rep.WebdriverOwn {
		t.Error("navigator.webdriver is an own property of navigator (must live on the prototype)")
	}
	if !rep.GetterNative {
		t.Error("Navigator.prototype.webdriver getter does not stringify as native")
	}
	if rep.Plugins == 0 || rep.MimeTypes == 0 || !rep.PluginsIsArray {
		t.Errorf("plugins=%d mimeTypes=%d instanceof PluginArray=%v, want a non-empty PluginArray",
			rep.Plugins, rep.MimeTypes, rep.PluginsIsArray)
	}
	if len(rep.Languages) == 0 || rep.Languages[0] != "en-US" {
		t.Errorf("navigator.languages = %v, want en-US first", rep.Languages)
	}
	if strings.Contains(rep.UserAgent, "Headless") {
		t.Errorf("navigator.userAgent names headless: %s", rep.UserAgent)
	}
	if rep.Brands == nil {
		t.Fatal("navigator.userAgentData missing (127.0.0.1 is a secure context)")
	}
	brands := strings.Join(rep.Brands, ",")
	if strings.Contains(brands, "Headless") || !strings.Contains(brands, "Google Chrome") {
		t.Errorf("userAgentData.brands = %v, want Google Chrome and no HeadlessChrome", rep.Brands)
	}
	if strings.Contains(secCHUA, "Headless") {
		t.Errorf("Sec-CH-UA names headless: %s", secCHUA)
	}

	// The asynchronous and frame-level patches: permissions agree with
	// Notification.permission, chrome.runtime exists on a secure page, and a
	// same-origin srcdoc frame reports the same navigator.
	extra, err := p.rodPage.Eval(`async () => {
	  const st = await navigator.permissions.query({name: 'notifications'});
	  const f = document.createElement('iframe');
	  f.srcdoc = '<p>x</p>';
	  document.body.appendChild(f);
	  const fw = f.contentWindow;
	  // The launcher's disable-notifications removes the Notification API;
	  // the patch only applies where it exists.
	  const want = typeof Notification === 'undefined' ? st.state
	    : (Notification.permission === 'default' ? 'prompt' : Notification.permission);
	  return JSON.stringify({
	    permsConsistent: st.state === want,
	    runtime: !!(window.chrome && window.chrome.runtime),
	    frameWebdriver: fw.navigator.webdriver,
	    framePlugins: fw.navigator.plugins.length,
	  });
	}`)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	var got struct {
		PermsConsistent bool `json:"permsConsistent"`
		Runtime         bool `json:"runtime"`
		FrameWebdriver  bool `json:"frameWebdriver"`
		FramePlugins    int  `json:"framePlugins"`
	}
	if err := json.Unmarshal([]byte(extra.Value.Str()), &got); err != nil {
		t.Fatalf("decode %q: %v", extra.Value.Str(), err)
	}
	t.Logf("extra: %+v", got)
	if !got.PermsConsistent {
		t.Error("permissions.query(notifications) disagrees with Notification.permission")
	}
	if !got.Runtime {
		t.Error("window.chrome.runtime missing on a secure page")
	}
	if got.FrameWebdriver || got.FramePlugins == 0 {
		t.Errorf("srcdoc frame: webdriver=%v plugins=%d", got.FrameWebdriver, got.FramePlugins)
	}
}

// TestStealthOffKeepsAutomationMarkers proves the report page can tell the
// difference: without stealth rod's enable-automation sets navigator.webdriver.
func TestStealthOffKeepsAutomationMarkers(t *testing.T) {
	rep, _ := loadStealthReport(t, config.StealthOff)
	if !rep.Webdriver {
		t.Error("navigator.webdriver is false with stealth off; the report page is not measuring the launcher flag")
	}
}
