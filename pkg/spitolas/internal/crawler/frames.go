package crawler

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"go.uber.org/zap"
)

// iframePrimeTimeout bounds the in-page priming work so a slow or unresponsive
// target cannot stall the crawl. Frames that finish loading before the deadline
// are captured by the network layer regardless.
const iframePrimeTimeout = 60 * time.Second

// iframeDiscoverScript reads the <iframe>/<frame> src URLs out of the live,
// post-render DOM and returns the same-origin ones as a JSON array of absolute
// URLs. It recurses into same-origin child-frame documents (nested frames),
// guarding every cross-document access so a cross-origin frame is skipped rather
// than throwing.
//
// Why this exists: a modern SPA login/registration flow (Salesforce Aura/
// Lightning, Angular, …) builds its iframes client-side after the framework
// hydrates — a reCAPTCHA host page, an embedded widget, an auth step — so the
// frame's URL (often carrying a reflected query parameter) appears nowhere in
// the served HTML or in any static JS string. A short headless visit that does
// not drive the exact flow which mounts the frame never requests it, so the page
// is never recorded and never scanned. Reading the rendered DOM surfaces the
// frames that did mount (on the index and on every state the crawler reaches),
// including ones injected after first paint; primeIframeAssets then fetches them
// so the network capture records the URL for the scanner.
//
// It deliberately only follows frames the live DOM actually contains — it never
// guesses frame names (that is the discovery phase's path brute-forcing job).
const iframeDiscoverScript = `(() => {
  const origin = location.origin;
  const HARDCAP = 500;
  const seen = new Set();
  const out = [];
  const add = (raw, baseURI) => {
    if (!raw || typeof raw !== 'string') return;
    raw = raw.trim();
    if (!raw || /^(about:|javascript:|data:|blob:|mailto:|tel:|#)/i.test(raw)) return;
    let abs;
    try { abs = new URL(raw, baseURI || document.baseURI); } catch (e) { return; }
    if (abs.protocol !== 'http:' && abs.protocol !== 'https:') return;
    if (abs.origin !== origin) return;          // same-origin only
    abs.hash = '';
    const href = abs.href;
    if (seen.has(href)) return;
    seen.add(href);
    out.push(href);
  };
  // Collect iframe/frame elements under a root, PIERCING shadow DOM: web-
  // component apps (a web-component design system, Stencil, Lit, Angular ShadowDom
  // encapsulation) render frames inside shadow roots, invisible to a plain
  // document.querySelectorAll. Walk every element's shadowRoot recursively.
  const collectFrames = (root, sink) => {
    let frames;
    try { frames = root.querySelectorAll('iframe, frame'); } catch (e) { frames = []; }
    for (const f of frames) sink.push(f);
    let all;
    try { all = root.querySelectorAll('*'); } catch (e) { all = []; }
    for (const el of all) {
      if (el.shadowRoot) { try { collectFrames(el.shadowRoot, sink); } catch (e) {} }
    }
  };
  // Breadth-first over same-origin documents (top document + accessible nested
  // frame documents). contentDocument throws / is null for cross-origin frames,
  // which we simply skip.
  const docs = [document];
  for (let i = 0; i < docs.length && out.length < HARDCAP; i++) {
    const d = docs[i];
    const frames = [];
    collectFrames(d, frames);
    for (const f of frames) {
      try { add(f.getAttribute('src'), d.baseURI); } catch (e) {}
      let cd = null;
      try { cd = f.contentDocument; } catch (e) { cd = null; }
      if (cd && docs.indexOf(cd) === -1) docs.push(cd);
    }
  }
  return JSON.stringify(out);
})()`

// primeIframeAssets harvests the same-origin <iframe>/<frame> sources present in
// the live DOM and fetches the ones not already primed this crawl, so the
// network layer records them. It is best-effort: any failure (eval error,
// timeout, context cancellation) is logged at debug and the crawl continues.
func (c *Crawler) primeIframeAssets(ctx context.Context, page *browser.Page) {
	if page == nil || c.config == nil || !c.config.IframePriming || !c.config.CrawlFrames {
		return
	}

	// Let subframes a framework injects after first paint fire and settle before
	// we read the DOM. rod's WaitStable (already run before capture) covers the
	// initial load; this absorbs the after-paint tail.
	page.WaitNetworkIdle(c.config.DOMStableTime, c.config.NetworkIdleTimeout)

	// Phase 1: read the frame sources out of the rendered DOM.
	raw, err := page.Eval(iframeDiscoverScript)
	if err != nil {
		zap.L().Debug("Iframe discovery failed", zap.Error(err))
		return
	}
	jsonStr, ok := raw.(string)
	if !ok || jsonStr == "" || jsonStr == "<nil>" {
		return
	}
	var discovered []string
	if err := parseJSONLinks(jsonStr, &discovered); err != nil || len(discovered) == 0 {
		return
	}

	// Cross-crawl dedup + cap: only fetch frames we have not primed yet.
	maxAssets := c.config.IframeMaxAssets
	if maxAssets <= 0 {
		maxAssets = 200
	}
	// Phase 2: fetch the new frame URLs in-page so they are captured.
	toFetch := c.selectUnprimedFrames(discovered, maxAssets)
	c.fetchURLsInPage(ctx, page, toFetch, "iframe")
}

// selectUnprimedFrames returns the URLs from in that have not been primed yet
// this crawl (marking them primed), capped at max. Safe for concurrent use.
func (c *Crawler) selectUnprimedFrames(in []string, max int) []string {
	c.primedFramesMu.Lock()
	defer c.primedFramesMu.Unlock()
	if c.primedFrames == nil {
		c.primedFrames = make(map[string]bool)
	}
	out := make([]string, 0, len(in))
	for _, u := range in {
		if max > 0 && len(out) >= max {
			break
		}
		if c.primedFrames[u] {
			continue
		}
		c.primedFrames[u] = true
		out = append(out, u)
	}
	return out
}

// navigateToFrame navigates to a specific frame by its path (e.g., "frame1.frame2").
// Returns the Page object for the target frame.
func (c *Crawler) navigateToFrame(page *browser.Page, framePath string) (*browser.Page, error) {
	if framePath == "" {
		return page, nil
	}

	// Split frame path into segments
	segments := strings.Split(framePath, ".")
	currentPage := page

	for _, segment := range segments {
		frameInfos, err := currentPage.FramesWithInfo()
		if err != nil {
			return nil, fmt.Errorf("failed to get frames: %w", err)
		}

		found := false
		for _, fi := range frameInfos {
			// Get frame identifier (FramesWithInfo already uses id before name)
			frameID := fi.ID
			if frameID == "" {
				frameID = fmt.Sprintf("frame%d", fi.Index)
			}
			if frameID == segment {
				currentPage = fi.Page
				found = true
				break
			}
		}

		if !found {
			return nil, fmt.Errorf("frame %q not found", segment)
		}
	}

	return currentPage, nil
}
