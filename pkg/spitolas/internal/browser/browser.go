package browser

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	chromium "github.com/vigolium/vigolium/internal/resources/spitolas"
	"github.com/vigolium/vigolium/pkg/browserprobe"
	"github.com/vigolium/vigolium/pkg/cftbrowser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/launcher/flags"
	"github.com/go-rod/rod/lib/proto"
	"github.com/vigolium/vigolium/internal/scratch"
	"go.uber.org/zap"
)

// Browser wraps rod.Browser with additional functionality.
type Browser struct {
	rodBrowser  *rod.Browser
	config      *config.Config
	launcher    *launcher.Launcher
	profileDir  string // Chromium user-data directory owned by this browser; removed by Close
	currentPage *Page  // Persistent page for session state preservation

	// uaOverride is the realistic User-Agent applied to every page (the real
	// browser UA with "HeadlessChrome" stripped). Computed once per browser
	// (uaOnce) so NewPage doesn't re-query the browser version per page/tab.
	uaOnce     sync.Once
	uaOverride string

	// crawlCtx, when set, is bound onto every page created by NewPage so that
	// the crawl's deadline/cancellation propagates into every rod operation
	// (navigation, WaitStable, clicks, element lookups, form fills) — not just
	// the Go-level loop checks. rod's Page.Timeout(d) derives from the page's
	// context, so a bound page caps each op at min(d, remaining-deadline) and
	// aborts in-flight CDP calls the moment the crawl context is cancelled.
	// Without this the spider can run far past max-duration: the deadline is
	// only polled between actions while individual browser operations block on
	// their own fixed rod timeouts (PageLoadTimeout=30s, ElementTimeout=5s).
	// The browser connection itself stays on the background context so capture
	// flushing and shutdown still work after the deadline fires.
	crawlCtx context.Context

	mu    sync.Mutex
	pages []*Page
}

// New creates a new browser instance.
func New(cfg *config.Config) (*Browser, error) {
	b := &Browser{
		config: cfg,
		pages:  make([]*Page, 0),
	}

	if err := b.launch(); err != nil {
		return nil, err
	}

	return b, nil
}

// launch starts the browser process, trying each candidate binary in priority
// order and falling through to the next whenever one fails to actually launch.
//
// Order: explicit browser_path → embedded engine binary → system Google Chrome
// → system Chromium → Chrome for Testing (cached, then downloaded) → rod's own
// auto-download. A binary that merely prints a version but crashes on real
// headless startup (e.g. some distro Chromium builds on a KVM guest) is
// therefore auto-recovered from — the scan falls back to a working browser (in
// practice Chrome for Testing) instead of failing outright. Only when every
// candidate fails does this return an aggregated error.
func (b *Browser) launch() error {
	candidates := b.browserCandidates()

	var attempts []string
	for _, c := range candidates {
		binPath, err := c.resolve()
		if err != nil {
			zap.L().Debug("browser candidate unavailable, skipping",
				zap.String("candidate", c.label), zap.Error(err))
			continue
		}

		l := b.newLauncher(binPath)
		u, err := l.Launch()
		if err != nil {
			// No l.Kill() here: launcher.Launch already kills the process on the
			// getURL/timeout failure path, and a failed cmd.Start leaves none —
			// a second Kill would just burn its built-in ~1s sleep for nothing.
			short := browserprobe.FirstLine(err.Error())
			zap.L().Warn("browser candidate failed to launch, falling back to next",
				zap.String("candidate", c.label),
				zap.String("bin", binPathOrAuto(binPath)),
				zap.String("error", short))
			attempts = append(attempts, fmt.Sprintf("%s [%s]: %s", c.label, binPathOrAuto(binPath), short))
			continue
		}

		browser := rod.New().ControlURL(u)
		if err := browser.Connect(); err != nil {
			l.Kill()
			zap.L().Warn("browser candidate connected but handshake failed, falling back to next",
				zap.String("candidate", c.label), zap.Error(err))
			attempts = append(attempts, fmt.Sprintf("%s [%s]: connect: %v", c.label, binPathOrAuto(binPath), err))
			continue
		}

		b.launcher = l
		b.profileDir = l.Get(flags.UserDataDir)
		b.rodBrowser = browser
		zap.L().Debug("browser launched",
			zap.String("candidate", c.label), zap.String("bin", binPathOrAuto(binPath)))
		return nil
	}

	if len(attempts) == 0 {
		hint := ""
		if isLinuxARM64For(runtime.GOOS, runtime.GOARCH) {
			hint = " — install one with: sudo apt-get install -y chromium"
		}
		return fmt.Errorf("failed to launch browser: no browser binary found%s", hint)
	}
	return fmt.Errorf("failed to launch browser: all %d candidate(s) failed: %s",
		len(attempts), strings.Join(attempts, "; "))
}

// browserCandidate is one binary to attempt, in priority order. resolve is lazy
// so expensive providers (the Chrome for Testing download) only run once every
// cheaper candidate has already failed.
type browserCandidate struct {
	label   string
	resolve func() (string, error) // returns bin path; "" means "let rod auto-download"
}

// browserCandidates builds the ordered candidate list for the current host. It
// resolves the platform-varying inputs (system browser binaries, GOOS/GOARCH)
// and hands them to buildBrowserCandidates, which owns the ordering.
func (b *Browser) browserCandidates() []browserCandidate {
	systemBins := systemBrowserBins(browserPreferenceOrderFor(runtime.GOOS), lookPathFound, validateBrowserBin)
	return buildBrowserCandidates(runtime.GOOS, runtime.GOARCH, b.config.BrowserPath, systemBins, b.getEmbeddedBrowserPath)
}

// buildBrowserCandidates assembles the ordered candidate list from already-
// resolved inputs. Platform (goos/goarch), the configured path, the resolved
// system browser bins, and the embedded-binary resolver are all injected, so the
// ordering — and the platform-specific tail (the linux/arm64 rod-auto-download
// skip) — is unit-testable on any host. See launch() for the order rationale.
func buildBrowserCandidates(goos, goarch, configPath string, systemBins []string, embedded func() (string, error)) []browserCandidate {
	var cands []browserCandidate
	add := func(label string, resolve func() (string, error)) {
		cands = append(cands, browserCandidate{label: label, resolve: resolve})
	}

	// 1. Explicit configured path — highest priority (e.g. spidering.browser_path).
	if configPath != "" {
		add("configured browser_path", func() (string, error) { return configPath, nil })
	}

	// 2. Embedded engine binary — only resolves for the ungoogled/fingerprint
	//    engines (or an embed_chromium build); a no-op for the default engine.
	add("embedded browser", embedded)

	// 3. System browsers, real Chrome first then Chromium. All resolvable
	//    binaries are enumerated (not just the first match) so a crash-on-launch
	//    Chromium can fall through to a working Chrome/Chromium, then to CfT.
	for _, p := range systemBins {
		add("system browser "+p, func() (string, error) { return p, nil })
	}

	// cftCandidate wraps a Chrome-for-Testing resolver with the shared
	// "is there a build for this platform?" guard so the two CfT rungs below
	// can't drift in how they gate (no build for e.g. linux/arm64).
	cftCandidate := func(fn func() (string, error)) func() (string, error) {
		return func() (string, error) {
			if !cftbrowser.IsSupported() {
				return "", fmt.Errorf("chrome for testing unsupported on %s/%s", goos, goarch)
			}
			return fn()
		}
	}

	// 4. Chrome for Testing — a previously cached copy (no network).
	add("Chrome for Testing (cached)", cftCandidate(cftbrowser.FindCachedBrowser))

	// 5. Chrome for Testing — download on the fly (network, last real resort).
	//    This is what recovers a host whose only system browser is broken.
	add("Chrome for Testing (download)", cftCandidate(func() (string, error) {
		zap.L().Info("No working system browser — downloading Chrome for Testing")
		return cftbrowser.EnsureBrowser(context.Background())
	}))

	// 6. rod's built-in auto-download (a browser rod fetches itself). Dropped
	//    ONLY on linux/arm64, where rod's download URLs are broken and would
	//    hang on a multi-minute fetch race. This does NOT make arm64 a
	//    second-class platform: an apt-installed system Chromium (candidate 3)
	//    — or the embedded ungoogled arm64 engine (candidate 2) — is the
	//    supported path there, exactly like everywhere else. What arm64 lacks is
	//    only the *automatic download* rungs (both CfT and rod publish no
	//    linux/arm64 build), so if no browser is installed launch() returns an
	//    "install chromium" hint instead of hanging.
	if !isLinuxARM64For(goos, goarch) {
		add("rod auto-download", func() (string, error) { return "", nil })
	}

	return cands
}

// isLinuxARM64For reports whether goos/goarch is linux/arm64. Only the automatic
// browser *download* fallbacks are unavailable there (neither rod nor Chrome for
// Testing ship a linux/arm64 binary); a system-installed Chromium is used
// normally. Parameterized by GOOS/GOARCH so it's testable on any host.
func isLinuxARM64For(goos, goarch string) bool {
	return goos == "linux" && goarch == "arm64"
}

// newLauncher builds a fresh, fully-configured launcher for a single launch
// attempt. A launcher.Launcher may only be Launch()ed once, so every candidate
// gets its own. An empty binPath leaves the binary unset so rod resolves or
// auto-downloads one.
func (b *Browser) newLauncher(binPath string) *launcher.Launcher {
	l := launcher.New()
	if binPath != "" {
		l = l.Bin(binPath)
	}

	// Pin the Chromium profile under this run's scratch instead of letting rod
	// pick $TMPDIR/rod/user-data/<random>, which it only ever removes through
	// launcher.Cleanup() - a call Close never made, so every launch stranded a
	// profile permanently (see the internal/scratch package doc for the scale).
	//
	// Cleanup() is not the fix: it blocks until the browser process exits, so a
	// wedged browser - exactly the case that leaks - would hang teardown. Owning
	// the path lets Close remove it directly, with scratch.Release as the
	// backstop for a run that never reaches Close at all.
	if dir, err := scratch.MkdirTemp("rod-profile-*"); err == nil {
		l = l.UserDataDir(dir)
	} else {
		zap.L().Debug("could not allocate a scratch browser profile; rod will use its own temp directory",
			zap.Error(err))
	}

	l.NoSandbox(true)
	l.Set("disable-web-security").
		Set("allow-running-insecure-content").
		Set("reduce-security-for-testing").
		Set("disable-ipc-flooding-protection").
		Set("disable-xss-auditor").
		Set("disable-bundled-ppapi-flash").
		Set("disable-plugins-discovery").
		Set("disable-default-apps").
		Set("disable-prerender-local-predictor").
		Set("disable-breakpad").
		Set("disable-crash-reporter").
		Set("disk-cache-size", "0").
		Set("disable-settings-window").
		Set("disable-notifications").
		Set("disable-speech-api").
		Set("disable-file-system").
		Set("disable-presentation-api").
		Set("disable-permissions-api").
		Set("disable-new-zip-unpacker").
		Set("disable-media-session-api").
		Set("disable-audio-output").
		Set("disable-dev-shm-usage").
		Set("no-experiments").
		Set("no-first-run").
		Set("no-default-browser-check").
		Set("no-pings").
		Set("no-service-autorun").
		Set("media-cache-size", "0").
		Set("use-fake-device-for-media-stream").
		Set("dbus-stub").
		Set("lang", "en-US").
		Set("disable-background-networking").
		// Disable HTTPS upgrade features to prevent Chrome from auto-upgrading HTTP to HTTPS
		// which causes timeout when target doesn't have HTTPS server
		Set("disable-features", "ChromeWhatsNewUI,HttpsUpgrades,HttpsFirstModeV2,HttpsFirstBalancedMode,HttpsFirstModeForAdvancedProtectionUsers,ImageServiceObserveSyncDownloadStatus,TrackingProtection3pcd,LensOverlay,AutomationControlled").
		Set("ignore-certificate-errors")

	// Add fingerprint flags for Ungoogled-Chromium
	if b.config.BrowserEngine == "ungoogled" || b.config.BrowserEngine == "fingerprint" {
		fingerprint := strconv.Itoa(rand.Intn(10000000) + 1)
		l = l.Set("fingerprint", fingerprint).
			Set("fingerprint-platform", "windows").
			// Set("timezone", "America/Los_Angeles").
			Set("fingerprint-brand", "Chrome")
		zap.L().Debug("Using Ungoogled-Chromium fingerprint",
			zap.String("fingerprint", fingerprint),
			zap.String("fingerprint-brand", "Chrome"))
	}

	l = l.Headless(b.config.Headless)

	// Set proxy if configured. Force HTTP/1.1 alongside it: intercepting proxies
	// (Burp, ZAP) routinely mishandle HTTP/2 frame translation, which Chrome
	// surfaces as net::ERR_HTTP2_PROTOCOL_ERROR and which fails navigation
	// outright rather than degrading gracefully.
	if b.config.ProxyURL != "" {
		l = applyProxy(l, b.config.ProxyURL)
		if b.config.ProxyAllowLoopback {
			// Chrome bypasses the proxy for localhost/127.0.0.1 by default;
			// <-loopback> drops that implicit rule so an intercepting proxy
			// (Burp) also captures traffic to a loopback target.
			l = l.Set("proxy-bypass-list", "<-loopback>")
		}
		zap.L().Debug("Proxy configured — forcing HTTP/1.1 (disable-http2, disable-quic)",
			zap.String("proxy", b.config.ProxyURL))
	}

	return l
}

// binPathOrAuto renders an empty bin path (rod auto-download) as "auto" for logs.
func binPathOrAuto(binPath string) string {
	if binPath == "" {
		return "auto-download"
	}
	return binPath
}

// applyProxy points the launcher at proxyURL and forces HTTP/1.1 over it.
// disable-http2 stops Chrome from negotiating HTTP/2 with the proxy (the source
// of net::ERR_HTTP2_PROTOCOL_ERROR through Burp/ZAP), and disable-quic stops it
// from routing around the proxy over QUIC/HTTP3, which an HTTP proxy can't
// intercept. No-op when proxyURL is empty so non-proxied scans keep HTTP/2.
func applyProxy(l *launcher.Launcher, proxyURL string) *launcher.Launcher {
	if proxyURL == "" {
		return l
	}
	return l.Proxy(proxyURL).
		Set("disable-http2").
		Set("disable-quic")
}

// SetCrawlContext binds ctx onto every page subsequently created by NewPage so
// the crawl deadline propagates into rod's per-operation timeouts. Call it once
// before the crawl starts creating pages. A nil ctx clears the binding. See the
// crawlCtx field doc for why this is required to honor max-duration.
func (b *Browser) SetCrawlContext(ctx context.Context) {
	b.mu.Lock()
	b.crawlCtx = ctx
	b.mu.Unlock()
}

// browserOpTimeout bounds a one-shot browser-level CDP op (page/tab create,
// list, close, version). Unlike page ops, these run on the browser's background
// context — NOT the crawl context bound onto pages — so without an explicit cap
// a wedged or unresponsive browser would hang them forever, including at
// teardown. Do NOT use the capped clone for long-lived loops (EachEvent).
const browserOpTimeout = 30 * time.Second

// boundedBrowser returns the rod browser capped at browserOpTimeout for a
// one-shot browser-level CDP call.
func (b *Browser) boundedBrowser() *rod.Browser {
	return b.rodBrowser.Timeout(browserOpTimeout)
}

// NewPage creates a new page (tab).
func (b *Browser) NewPage() (*Page, error) {
	// Create on the raw browser, NOT a Timeout-bounded clone: rod sets the new
	// page's .browser to whatever browser created it, and page ops that route
	// through the browser context would then inherit (and outlive into) that short
	// timeout — expiring the long-lived crawl page browserOpTimeout after creation.
	// Page creation is a quick browser-level call; the wedged-browser cap matters
	// for the one-shot ops (Close/Pages/version), which don't hand back a
	// long-lived object.
	rodPage, err := b.rodBrowser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		return nil, fmt.Errorf("failed to create page: %w", err)
	}

	// Bind the crawl context (if set) so every rod operation on this page — and
	// every element derived from it — inherits the crawl's deadline and
	// cancellation. rod returns a clone from Context(), so use the clone.
	b.mu.Lock()
	crawlCtx := b.crawlCtx
	b.mu.Unlock()
	if crawlCtx != nil {
		rodPage = rodPage.Context(crawlCtx)
	}

	// Enable Network domain on this page for traffic capture.
	// Browser.EachEvent only enables domains at browser level, but Network events
	// are only emitted from pages that have the Network domain explicitly enabled.
	_ = proto.NetworkEnable{}.Call(rodPage)

	// Present as a normal browser, not HeadlessChrome. Many SPAs gate their
	// content/locale routing (and some anti-bot layers gate rendering) on a real
	// User-Agent + Accept-Language; the default headless UA both advertises
	// automation and can trigger a degraded experience where the app never renders
	// its real content. Strip "Headless" from the actual UA (keeping the accurate
	// Chrome version) and pin Accept-Language to en-US. The UA is resolved once per
	// browser; the override itself is a page-level CDP call, so it's applied here.
	b.uaOnce.Do(func() {
		if ver, verr := (proto.BrowserGetVersion{}).Call(b.boundedBrowser()); verr == nil {
			b.uaOverride = strings.ReplaceAll(ver.UserAgent, "HeadlessChrome", "Chrome")
		}
	})
	if b.uaOverride != "" {
		_ = proto.NetworkSetUserAgentOverride{
			UserAgent:      b.uaOverride,
			AcceptLanguage: "en-US,en;q=0.9",
		}.Call(rodPage)
	}

	page := &Page{
		rodPage: rodPage,
		config:  b.config,
		browser: b,
	}

	// This runs in background and automatically accepts all JS dialogs.
	page.setupAutoDialogHandler()

	b.mu.Lock()
	b.pages = append(b.pages, page)
	b.mu.Unlock()

	return page, nil
}

// Pages returns all open pages.
func (b *Browser) Pages() []*Page {
	b.mu.Lock()
	defer b.mu.Unlock()

	result := make([]*Page, len(b.pages))
	copy(result, b.pages)
	return result
}

// CurrentPage returns the current persistent page, or nil if none exists.
// CRITICAL FIX: This allows page reuse across actions to preserve session state.
func (b *Browser) CurrentPage() *Page {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.currentPage
}

// SetCurrentPage sets the current persistent page.
func (b *Browser) SetCurrentPage(page *Page) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.currentPage = page
}

// RodBrowser returns the underlying rod.Browser instance.
// Used for browser-level operations like traffic capture.
func (b *Browser) RodBrowser() *rod.Browser {
	return b.rodBrowser
}

// UserAgent returns the User-Agent the browser presents to sites — the real
// Chrome UA with "HeadlessChrome" rewritten to "Chrome" (see NewPage). Empty
// until the first page is created. Callers harvest this after a crawl so
// downstream phases can pin the exact UA the WAF issued its clearance cookie to.
func (b *Browser) UserAgent() string {
	return b.uaOverride
}

// HarvestCookies returns the browser's current cookie jar as net/http cookies.
// Called at the end of a crawl to carry the session (including any WAF/bot
// clearance cookies the real browser earned) forward into later scan phases.
// Uses the timeout-bounded browser handle so a wedged browser can't hang the
// harvest.
func (b *Browser) HarvestCookies() ([]*http.Cookie, error) {
	if b.rodBrowser == nil {
		return nil, fmt.Errorf("no browser available")
	}
	raw, err := b.boundedBrowser().GetCookies()
	if err != nil {
		return nil, err
	}
	cookies := make([]*http.Cookie, 0, len(raw))
	for _, c := range raw {
		if c == nil || c.Name == "" {
			continue
		}
		cookies = append(cookies, &http.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Secure:   c.Secure,
			HttpOnly: c.HTTPOnly,
		})
	}
	return cookies, nil
}

// closePageWithTimeout attempts to close a page with timeout and retry logic.
// Returns error only if ALL retries fail.
func closePageWithTimeout(rodPage *rod.Page, timeout time.Duration, maxRetries int) error {
	targetID := rodPage.TargetID

	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Create channel for close result
		resultChan := make(chan error, 1)

		// Run Close() in goroutine with timeout protection
		go func() {
			resultChan <- rodPage.Close()
		}()

		// Wait for either completion or timeout
		select {
		case err := <-resultChan:
			if err == nil {
				if attempt > 1 {
					zap.L().Debug("Page closed successfully after retry",
						zap.String("target_id", string(targetID)),
						zap.Int("attempt", attempt))
				}
				return nil
			}
			zap.L().Warn("Page close failed, will retry",
				zap.String("target_id", string(targetID)),
				zap.Error(err),
				zap.Int("attempt", attempt),
				zap.Int("max_retries", maxRetries))

		case <-time.After(timeout):
			zap.L().Warn("Page close timed out, will retry",
				zap.String("target_id", string(targetID)),
				zap.Duration("timeout", timeout),
				zap.Int("attempt", attempt),
				zap.Int("max_retries", maxRetries))
		}

		// Exponential backoff before retry (50ms, 100ms, 150ms)
		if attempt < maxRetries {
			backoff := time.Duration(50*attempt) * time.Millisecond
			time.Sleep(backoff)
		}
	}

	return fmt.Errorf("failed to close page %s after %d attempts", targetID, maxRetries)
}

// CloseOtherWindows closes all pages except the current one with timeout protection.
// to get ALL actual browser windows (including those opened by target="_blank" or window.open()).
//
// CRITICAL: Uses timeout + retry to prevent deadlocks when pages are slow to close.
// This is essential for target="_blank" links which may open pages faster than we can track them.
func (b *Browser) CloseOtherWindows() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.currentPage == nil {
		zap.L().Debug("CloseOtherWindows: no current page set, nothing to close")
		return nil
	}

	currentTargetID := b.currentPage.rodPage.TargetID

	// Query all browser pages including those opened by target="_blank" or window.open()
	allPages, err := b.boundedBrowser().Pages()
	if err != nil {
		zap.L().Error("Failed to query browser pages", zap.Error(err))
		return fmt.Errorf("failed to query browser pages: %w", err)
	}

	zap.L().Debug("CloseOtherWindows: closing extra pages",
		zap.Int("total_pages", len(allPages)),
		zap.String("current_target", string(currentTargetID)))

	// Close pages not matching current target with timeout protection
	closedCount := 0
	failedCount := 0

	for _, rodPage := range allPages {
		if rodPage.TargetID == currentTargetID {
			continue
		}

		// Attempt to close with timeout (5s per attempt, 3 retries)
		err := closePageWithTimeout(rodPage, 5*time.Second, 3)
		if err != nil {
			zap.L().Warn("Failed to close page, continuing anyway",
				zap.String("target_id", string(rodPage.TargetID)),
				zap.Error(err))
			failedCount++
		} else {
			closedCount++
		}
	}

	zap.L().Debug("CloseOtherWindows: completed",
		zap.Int("closed", closedCount),
		zap.Int("failed", failedCount))

	// Reset internal tracking to only current page
	b.pages = []*Page{b.currentPage}

	// Return error if ALL pages failed to close (indicates serious problem)
	if failedCount > 0 && closedCount == 0 && len(allPages) > 1 {
		return fmt.Errorf("failed to close any of %d extra pages", len(allPages)-1)
	}

	return nil
}

// Close closes the browser.
func (b *Browser) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Close all pages
	for _, page := range b.pages {
		_ = page.Close()
	}
	b.pages = nil

	// Close browser. Cap it so a wedged browser can't hang teardown forever
	// (the deferred pool.Close at the end of a crawl runs through here).
	var closeErr error
	if b.rodBrowser != nil {
		closeErr = b.boundedBrowser().Close()
	}

	// Remove the Chromium profile whether or not the browser closed cleanly: a
	// browser that failed to shut down is exactly the case that used to strand
	// its profile. Done after the close above so the process is no longer
	// writing into it.
	if b.profileDir != "" {
		if err := os.RemoveAll(b.profileDir); err != nil {
			zap.L().Debug("could not remove the browser profile directory",
				zap.String("dir", b.profileDir), zap.Error(err))
		}
		b.profileDir = ""
	}

	return closeErr
}

// IsConnected returns true if browser is connected.
func (b *Browser) IsConnected() bool {
	return b.rodBrowser != nil
}

// browserPreferenceOrderFor is the OS-specific list of system browser binaries
// to try, in priority order: real Google Chrome first, then Chromium. (Chrome
// for Testing is handled separately by browserCandidates, always after these.)
// Both bare names — resolved via PATH — and absolute fallbacks are listed; the
// absolute paths cover the apt layout where the real binary lives under
// /usr/lib/chromium and the snap stub sits in /usr/bin. Duplicates that resolve
// to the same path are collapsed by systemBrowserBins. Parameterized by GOOS so
// the ordering can be unit-tested on any host.
func browserPreferenceOrderFor(goos string) []string {
	return browserPreferenceOrderForEnv(goos, os.Getenv)
}

// browserPreferenceOrderForEnv is browserPreferenceOrderFor with the environment
// lookup injected. The Windows list is built from LOCALAPPDATA/ProgramFiles, so
// without this seam it could only be exercised on a Windows host — the same
// reason systemBrowserBins takes its lookPath as a parameter.
func browserPreferenceOrderForEnv(goos string, getenv func(string) string) []string {
	switch goos {
	case "linux":
		return []string{
			// Google Chrome (real).
			"google-chrome-stable", "google-chrome", "chrome",
			"/usr/bin/google-chrome-stable", "/usr/bin/google-chrome",
			// Chromium.
			"chromium", "chromium-browser",
			"/usr/bin/chromium", "/usr/bin/chromium-browser",
			"/snap/bin/chromium",
			"/usr/lib/chromium/chromium",
			"/usr/lib/chromium-browser/chromium-browser",
		}
	case "darwin":
		return []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"google-chrome", "chrome",
			"/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"chromium",
		}
	case "windows":
		// Chrome is essentially never on PATH on Windows, so the absolute
		// install locations carry this list; the bare names stay first so a
		// user who *did* put one on PATH keeps that choice. Per-user installs
		// (LOCALAPPDATA) are listed before machine-wide ones because when both
		// exist the per-user one is what that user actually launches.
		paths := []string{"chrome"}
		local := getenv("LOCALAPPDATA")
		progFiles := envOr(getenv, "ProgramFiles", `C:\Program Files`)
		progFiles86 := envOr(getenv, "ProgramFiles(x86)", `C:\Program Files (x86)`)
		if local != "" {
			paths = append(paths, winPath(local, `Google\Chrome\Application\chrome.exe`))
		}
		paths = append(paths,
			winPath(progFiles, `Google\Chrome\Application\chrome.exe`),
			winPath(progFiles86, `Google\Chrome\Application\chrome.exe`),
		)
		if local != "" {
			// Canary, after stable Chrome and before Chromium (mirrors darwin).
			paths = append(paths, winPath(local, `Google\Chrome SxS\Application\chrome.exe`))
		}
		paths = append(paths, "chromium")
		if local != "" {
			paths = append(paths, winPath(local, `Chromium\Application\chrome.exe`))
		}
		return append(paths, winPath(progFiles, `Chromium\Application\chrome.exe`))
	default:
		return []string{"chrome", "chromium"}
	}
}

// envOr returns the named environment variable, or fallback when it is unset.
// The literal fallbacks matter on a stripped environment (a service account, a
// CI shell) where ProgramFiles may be absent but the standard location is still
// correct.
func envOr(getenv func(string) string, name, fallback string) string {
	if v := getenv(name); v != "" {
		return v
	}
	return fallback
}

// winPath joins a Windows base directory and a relative Windows path with a
// literal backslash. filepath.Join is deliberately not used: it joins with the
// *host's* separator, so building these on a linux/darwin machine (which the
// unit tests do) would emit "C:\Program Files/Google\Chrome\...".
func winPath(base, rel string) string {
	return strings.TrimRight(base, `\`) + `\` + rel
}

// lookPathFound resolves name via exec.LookPath, returning the absolute path and
// whether it was found. Split out so systemBrowserBins can be unit-tested with a
// stubbed lookup.
func lookPathFound(name string) (string, bool) {
	p, err := exec.LookPath(name)
	if err != nil {
		return "", false
	}
	return p, true
}

// systemBrowserBins returns the resolvable, validated system browser binaries in
// the given preference order, deduplicated by resolved path. Real Chrome sorts
// ahead of Chromium so a working Chrome is preferred, while still enumerating
// every binary so launch() can fall through a crash-on-launch one. lookPath and
// validate are injected for testing (production: lookPathFound + validateBrowserBin).
func systemBrowserBins(order []string, lookPath func(string) (string, bool), validate func(string) bool) []string {
	var out []string
	seen := make(map[string]bool)
	for _, name := range order {
		p, ok := lookPath(name)
		if !ok || seen[p] {
			continue
		}
		seen[p] = true // mark before validate so a shared path is validated once
		if !validate(p) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// validateBrowserBin checks if a browser binary is a real browser executable
// (not a snap stub or broken wrapper). On Ubuntu, apt install chromium-browser
// installs a shell script at /usr/bin/chromium-browser that just prints
// "Please install it with: snap install chromium" and exits.
func validateBrowserBin(binPath string) bool {
	// Chrome on Windows is a GUI-subsystem binary: `chrome.exe --version` has
	// no console to write to, so it exits without printing anything. Probing by
	// output would therefore reject every real Chrome on Windows. Fall back to
	// "the file is there and is a file" — the candidate paths this validates
	// are specific install locations, not guesses, and a genuinely broken
	// binary surfaces when the launch itself fails rather than silently.
	if runtime.GOOS == "windows" {
		info, err := os.Stat(binPath)
		return err == nil && info.Mode().IsRegular()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	output := string(out)
	// Snap stubs print "requires the chromium snap to be installed"
	if strings.Contains(output, "snap") {
		return false
	}
	// A real browser prints a version line like "Chromium 124.0.6367.60"
	return strings.Contains(output, "Chromium") ||
		strings.Contains(output, "Chrome") ||
		strings.Contains(output, "Microsoft Edge")
}

// getEmbeddedBrowserPath returns the path to the embedded browser binary based on config.
func (b *Browser) getEmbeddedBrowserPath() (string, error) {
	engine := b.config.BrowserEngine
	if engine == "" {
		engine = "chromium" // Default
	}

	// Map engine name to chromium.BrowserEngine
	var browserEngine chromium.BrowserEngine
	switch engine {
	case "chromium":
		browserEngine = chromium.EngineChromium
	case "ungoogled":
		browserEngine = chromium.EngineUngoogled
	case "fingerprint":
		browserEngine = chromium.EngineFingerprint
	default:
		return "", fmt.Errorf("unknown browser engine: %s", engine)
	}

	return chromium.GetBrowserPath(browserEngine, "")
}

// Pool manages a pool of browsers.
type Pool struct {
	config   *config.Config
	browsers []*Browser
	mu       sync.Mutex
}

// NewPool creates a new browser pool.
func NewPool(cfg *config.Config) (*Pool, error) {
	pool := &Pool{
		config:   cfg,
		browsers: make([]*Browser, 0),
	}

	// Create initial browsers
	for i := 0; i < cfg.BrowserCount; i++ {
		browser, err := New(cfg)
		if err != nil {
			_ = pool.Close()
			return nil, fmt.Errorf("failed to create browser %d: %w", i, err)
		}
		pool.browsers = append(pool.browsers, browser)
	}

	return pool, nil
}

// SetCrawlContext binds ctx onto every browser in the pool so pages they create
// inherit the crawl deadline/cancellation. Call before the crawl starts.
func (p *Pool) SetCrawlContext(ctx context.Context) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, browser := range p.browsers {
		browser.SetCrawlContext(ctx)
	}
}

// Get returns a browser from the pool.
func (p *Pool) Get() *Browser {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.browsers) == 0 {
		return nil
	}

	// Round-robin selection
	browser := p.browsers[0]
	p.browsers = append(p.browsers[1:], browser)
	return browser
}

// Close closes all browsers in the pool.
func (p *Pool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var lastErr error
	for _, browser := range p.browsers {
		if err := browser.Close(); err != nil {
			lastErr = err
		}
	}
	p.browsers = nil

	return lastErr
}

// Size returns the number of browsers in the pool.
func (p *Pool) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.browsers)
}

// WaitContext creates a context with timeout.
func WaitContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout > 0 {
		return context.WithTimeout(ctx, timeout)
	}
	return ctx, func() {}
}
