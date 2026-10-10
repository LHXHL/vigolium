package crawler

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/state"
)

// initializeIndexState loads the initial page and captures the index state.
func (c *Crawler) initializeIndexState(ctx context.Context) error {
	zap.L().Debug("Initializing index state")

	br := c.browser
	if br == nil {
		return fmt.Errorf("no browser available")
	}

	page, err := br.NewPage()
	if err != nil {
		return err
	}

	// Set as current page so executeActionDFS can access it. It is the first
	// tab's page; any extra tabs are opened when the crawl loop starts.
	br.SetCurrentPage(page)
	c.primary.page = page

	// Seed operator-supplied authentication (cookies + extra headers) before the
	// first navigation so the crawl explores authenticated rather than only the
	// unauthenticated shell. A failure is recorded in Stats.AuthState; with
	// RequireAuth it fails the crawl instead of letting it run anonymously.
	if err := c.seedPageAuth(page); err != nil {
		return err
	}

	// Navigate to target URL
	url := c.config.URL.String()
	if c.config.BasicAuthUser != "" {
		url = c.config.GetBasicAuthURL()
	}

	zap.L().Debug("Navigating to target", zap.String("url", c.config.URL.String()))
	zap.L().Debug("Navigation URL prepared", zap.String("url", url))

	// Retry the very first navigation a few times. A transient transport error
	// (e.g. net::ERR_CONNECTION_RESET, common on the first connect through an
	// intercepting proxy like Burp) can fail an otherwise-reachable target, and
	// aborting here kills the whole spidering run for that target. Retrying rules
	// out a one-off browser/network hiccup before we give up.
	navErr := navigateWithRetry(ctx, url, initNavRetryBackoff, func() error {
		return page.NavigateCtx(ctx, url)
	})
	if navErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("failed to navigate: %w%s", navErr, certRejectedHint(navErr))
	}

	// Check wait conditions
	c.checkWaitConditions(ctx, page)

	// NOTE: no explicit WaitStable here — NavigateCtx already waited for the DOM
	// to stabilize (WaitStable(DOMStableTime)) as part of the navigation above, so
	// repeating it only doubled the settle. The heavier SPA settle below picks up
	// anything still in flight.

	// Let a heavy SPA finish its bootstrap XHR chain (config/i18n/content/feature
	// flags) before we snapshot the page and extract clickables — otherwise we
	// capture a half-rendered shell whose login CTA and data calls have not landed
	// yet. Then clear any cookie-consent overlay so it neither blocks the real
	// content from rendering nor masks the elements we extract/click, and scroll
	// the page so content/assets that only load as sections enter the viewport are
	// requested and captured.
	c.settleSPA(ctx, page)
	c.dismissConsentOverlays(ctx, page)
	c.scrollToLoadContent(ctx, page)

	// Decide what to do about an off-host start redirect (SSO wall vs. relocated
	// app) BEFORE any priming or extraction, so an adopted host is in scope by the
	// time the crawl loop follows links — and so a denied login wall is known
	// before anything below touches the page.
	//
	// Position is load-bearing. The two priming steps that follow fetch up to
	// several hundred URLs apiece from the page's OWN origin, which on a walled
	// start is the identity provider's. Classifying after them left the single
	// largest burst of IdP traffic in this function ungated, and made the guard
	// positional: any helper added above the classification would be silently
	// unguarded again.
	landingURL, _ := page.URL()
	c.evaluateStartRedirect(page, landingURL)
	walled := c.startWalled.Load()

	if !walled {
		// Prime service-worker assets: fetch the files a PWA service worker would
		// pre-cache (e.g. Angular's lazy webpack chunks listed in ngsw.json) so the
		// network capture records them. A short headless visit never runs the
		// worker's precache, so these are otherwise missed.
		c.primeServiceWorkerAssets(ctx, page)

		// Prime iframe sources: fetch the same-origin <iframe>/<frame> URLs present
		// in the rendered DOM (including frames injected client-side after first
		// paint) so the page they point at — and any reflected query parameters on
		// it — is recorded and scanned even when the served HTML never linked it.
		c.primeIframeAssets(ctx, page)
	}

	// Capture index state
	zap.L().Debug("Capturing index state")
	indexState, err := c.captureState(ctx, page, 0)
	if err != nil {
		return fmt.Errorf("failed to capture index state: %w", err)
	}
	zap.L().Debug("Index state captured",
		zap.String("state_id", indexState.ID),
		zap.String("url", indexState.URL),
		zap.Int("dom_size", len(indexState.StrippedDOM)))

	// Add to graph
	c.graph.AddState(indexState)
	c.candidates.RecordStateCreation(indexState.ID)
	c.mu.Lock()
	c.stats.StatesDiscovered++
	c.mu.Unlock()

	// RLCRAWLER PARITY: Register index state with MAB policy
	if c.mabPolicy != nil {
		c.mabPolicy.AddState(indexState.ID)
	}

	c.primary.stateMachine = state.NewStateMachine(c.graph, indexState)

	c.session = NewCrawlSession(c.config, indexState)

	c.primary.crawlPath = state.NewCrawlPath(indexState.ID)

	zap.L().Debug("Index state captured", zap.String("state", indexState.Name))

	// The landing is a denied login wall. Stop here rather than running the rest
	// of this function against it: everything below interacts with the page —
	// extracting and firing actions, filling and submitting its forms, priming
	// its anchors, harvesting its inline URLs — and the page belongs to somebody
	// else's identity provider. The index state and the redirect chain that got us
	// here are already recorded, which is the only part worth keeping.
	if walled {
		zap.L().Info("Spidering: landing is a login wall — skipping page interaction",
			zap.String("landing", landingURL))
		return nil
	}

	// Extract fragments
	c.extractFragments(page, indexState)

	// Extract initial actions (check crawl conditions first)
	if c.shouldCrawl(page) {
		c.extractor.SetCurrentState(indexState.ID)
		actions, err := c.extractor.Extract(ctx, page)
		if err != nil {
			zap.L().Debug("Failed to extract actions", zap.Error(err))
		} else {
			c.candidates.AddActions(actions, indexState.ID)
			added := len(actions)
			zap.L().Debug("Extracted actions from index state", zap.Int("count", added))
		}

		// NOTE: Frame extraction is already handled by c.extractor.Extract() which
		// recursively processes frames with correct framePath. No separate call needed.
	}

	// Drive the login CTA once. An unauthenticated visit to many enterprise apps
	// bounces to a portal landing whose "Log on" button kicks off an OAuth/SAML/SSO
	// navigation chain (… /oauth2/authorize → /idp/login → SAML → vendor login). The
	// normal state machine may never click it — it triggers a full cross-origin
	// navigation away from the landing — so the entire flow, and every URL it
	// touches, is missed. Clicking it here lets the network capture record the chain
	// and the destination login page's own XHRs; we then return to the landing so
	// the loop resumes from a known state.
	//
	// Runs BEFORE form-filling: a cookie-consent preference form (OneTrust et al.)
	// can carry dozens of controls that the form filler spends the element timeout
	// on apiece, which would otherwise burn the whole spider budget before the
	// login CTA is ever driven.
	c.primeLoginCTA(ctx, page, indexState.URL)

	// Fill forms if present.
	if c.config.FormFillEnabled {
		zap.L().Debug("Form filling enabled, detecting forms")
		c.fillFormsIfPresent(page, "")
	}

	// Submit GET forms (search/filter boxes) so their result URLs — e.g.
	// /catalog?searchTerm=a — are requested and captured. The interaction crawl
	// only submits a form when its submit control happens to be clicked, which the
	// bounded action budget frequently never selects; this makes it deterministic.
	// The forms were just filled above, so submitGetForms skips its own fill.
	c.submitGetForms(ctx, page, true)

	// Trigger POST forms (a JS-driven stock check → /catalog/product/stock, a
	// newsletter subscribe, etc.) so their endpoints are exercised and captured.
	// GET-form synthesis above already re-filled the forms, so skip a repeat fill.
	c.submitPostForms(ctx, page, true)

	// Fetch same-origin parameterized <a href> links (e.g. React-rendered
	// /catalog?category=Books filter links) so they are captured even when the
	// interaction budget never clicks them.
	c.primeAnchorLinks(ctx, page)

	// Scrape URL-like strings out of the rendered document's comments and inline
	// script — locations reachable by no click.
	c.harvestSpeculativeLinks(ctx, page)

	// If the landing itself is a login form, try common credentials (deep
	// intensity only, confirmed-login-gated) so the crawl can proceed
	// authenticated. Runs after form-filling so the fixed-identity fill has
	// already seeded the fill context that this pass reuses.
	c.attemptLoginCredentials(ctx, page)

	// Complete a public signup form, if the app has one and the operator opted
	// in, so the crawl continues as an authenticated user. Runs after the
	// credential pass so an existing-account login is preferred over creating a
	// new one; the identity it registers is reused by later login attempts.
	c.attemptSelfRegistration(ctx, page)

	return nil
}

// initNavAttempts is the total number of times the initial target navigation is
// attempted (1 initial try + 2 retries) before the crawl gives up on a target.
const initNavAttempts = 3

// initNavRetryBackoff is the pause between initial-navigation attempts.
const initNavRetryBackoff = 2 * time.Second

// navigateWithRetry calls navFn up to initNavAttempts times, pausing backoff
// between attempts, to ride out transient navigation failures (connection
// resets, proxy hiccups). Context cancellation aborts immediately and is never
// retried; the navigation error is returned only after every attempt fails. The
// navigation itself is injected so the retry policy can be unit-tested without a
// browser. url is used for logging only.
// certRejectedHint names the way out when navigation failed on a certificate:
// the browser only verifies TLS when spidering.browser_compat.ignore_tls_errors
// was turned off, so a self-signed local app needs it back on.
func certRejectedHint(err error) string {
	if err == nil || !strings.Contains(err.Error(), "ERR_CERT_") {
		return ""
	}
	return " (certificate rejected — re-run with --browser-insecure, or set spidering.browser_compat.ignore_tls_errors: true, if this is a local test app)"
}

func navigateWithRetry(ctx context.Context, url string, backoff time.Duration, navFn func() error) error {
	var lastErr error
	for attempt := 1; attempt <= initNavAttempts; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err := navFn()
		if err == nil {
			if attempt > 1 {
				zap.L().Info("Initial navigation succeeded on retry",
					zap.String("url", url), zap.Int("attempt", attempt))
			}
			return nil
		}
		// A cancelled/expired context surfaces as a navigation error; don't
		// retry it — the run is over.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		lastErr = err
		if attempt < initNavAttempts {
			zap.L().Warn("Initial navigation failed, retrying",
				zap.String("url", url),
				zap.Int("attempt", attempt),
				zap.Int("max_attempts", initNavAttempts),
				zap.Error(err))
			if sleepErr := sleepWithContext(ctx, backoff); sleepErr != nil {
				return sleepErr
			}
		}
	}
	return lastErr
}
