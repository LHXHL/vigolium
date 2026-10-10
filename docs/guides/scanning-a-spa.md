# Scanning a Single-Page Application (SPA)

## Overview

Single-page applications built with frameworks like React, Angular, or Vue render content dynamically in the browser. Traditional crawlers that parse raw HTML will miss most endpoints because routes, API calls, and UI interactions are driven by JavaScript. Vigolium addresses this with browser-based spidering that executes JavaScript and captures network traffic as it navigates the application.

## How Vigolium Handles SPAs

Vigolium's browser-based spidering engine (Spitolas) uses Chromium via the Chrome DevTools Protocol (CDP) to:

- **Render JavaScript**: Pages are fully rendered in a headless browser, allowing Vigolium to discover routes that only exist after JS execution.
- **Capture network traffic**: All HTTP requests made by the application (XHR, fetch, WebSocket upgrades) are intercepted via CDP and fed into the scanner as inputs.
- **Interact with the DOM**: The spider clicks buttons, fills forms, and triggers UI events to discover endpoints behind user interactions.
- **Extract client-side routes**: SPA router configurations and navigation links are identified even when they do not result in full page loads.

## Running a SPA Scan

The default `balanced` strategy includes browser spidering automatically:

```bash
vigolium scan -t https://spa.example.com
```

For deeper coverage, use the `deep` strategy which increases spidering depth and interaction aggressiveness:

```bash
vigolium scan -t https://spa.example.com --strategy deep
```

If you only want the spidering phase (e.g., for reconnaissance), isolate it with `--only`:

```bash
vigolium scan -t https://spa.example.com --only spidering
```

## Browser Requirements

Vigolium requires a Chromium-based browser for spidering. On first use, it automatically downloads a compatible Chromium binary. No manual installation is needed in most cases.

For environments where auto-download is not possible (air-gapped systems, containers), you can:

1. Pre-install Chromium and set `spidering.browser_path`.
2. Build an embedded binary that bundles Chromium:
   ```bash
   make deps-chrome && make build-embedded
   ```

To verify the browser is available:

```bash
vigolium doctor --json
# Install a managed Chrome for Testing when needed
vigolium doctor --fix --only chrome
```

## Tuning Spidering

Spidering behavior is configurable via `vigolium-configs.yaml` or CLI flags:

```yaml
spidering:
  max_depth: 5            # 0 means unlimited
  max_states: 100         # 0 means unlimited
  max_duration: 10m       # Go duration string
  max_consecutive_fails: 100
  browser_count: 1        # one browser per crawl; >1 is clamped to 1
  tabs: 1                 # tabs of that browser crawling in parallel (max 16)
  strategy: adaptive      # normal, random, oldest_first, shallow_first, adaptive
  browser_engine: chromium # chromium, ungoogled, fingerprint
  headless: true
  no_cdp: false
  max_listener_probe_nodes: 2000  # 0 = 2000, -1 = no cap
  no_forms: false
```

For large SPAs, increase `max_states`, depth, or duration. CLI
`--spider-max-time`, `--browsers`, `--browser-engine`, `--headed`, `--no-cdp`,
and `--no-forms` override the common runtime controls. `browser_count` /
`--browsers` above 1 does not add parallelism: the crawler drives one browser
and clamps the count to 1 (with a warning). `spidering.tabs` does: N tabs of
that browser share one state graph and frontier, each claiming a state and
firing its actions while the others work elsewhere. It stays `1` at every
intensity until a multi-tab soak has passed. Tabs share one cookie jar, so on
an app where a click can log the session out, set `tab_isolation: context` to
give each extra tab its own. To crawl several targets at once, run them as
separate processes.

### Web components and shadow DOM

The crawler finds clickables inside web components (Lit, Stencil, Angular
`ShadowDom` encapsulation, design systems) as well as in the light DOM:

- Elements matching the click selectors are found in every open shadow root,
  every closed shadow root (through CDP; no page script can see inside one),
  and same-origin iframes that a component renders inside its shadow root.
- With CDP detection on (the default; `--no-cdp` turns it off), one pierced
  `DOMDebugger.getEventListeners` call per state finds every element with a
  `click` listener, closed roots included. `max_listener_probe_nodes` caps how
  many of those become candidates per state.

An element behind a shadow boundary is identified by a locator: the XPath of
each shadow host, outermost first, then the element's XPath under the last
root, e.g.
`{"hostChain":["/html[1]/body[1]/x-cart[1]"],"innerXPath":"/div[1]/button[1]"}`.
This is the action's identification in crawl graphs (`how: "locator"`).
Light-DOM elements keep their plain XPath. Iframes in the light DOM are still
crawled as frames; an iframe nested inside a frame that a shadow root hosts is
not crawled.

What the crawl may change (form edits, submissions, uploads, account actions,
dialog answers) and which browser security exceptions are in force are
explained in [Browser policy](browser-policy.md).

## Common Issues

### Browser Not Found

If you see an error about a missing browser executable:

- Ensure you have internet access for the auto-download, or set `spidering.browser_path` to a local Chromium installation.
- In Docker containers, use the embedded build or install Chromium in the image.

### Timeouts

SPAs with heavy client-side rendering or slow APIs may cause page load timeouts:

- Increase `spidering.max_duration` or pass `--spider-max-time`.
- Ensure the target application is responsive and accessible from the scanner host.

### Headless Detection

Some applications block headless browsers. Vigolium applies common evasion techniques by default, but if the application still blocks requests:

- Pass `--headed` or set `spidering.headless: false` (requires a display server or Xvfb).
- Set `scanning_strategy.http.user_agent` or `VIGOLIUM_DEFAULT_UA`.
- Consider feeding pre-recorded traffic (HAR, Burp XML) as input instead of relying on live spidering.
