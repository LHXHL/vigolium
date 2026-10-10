# Native Scan: Running Phases Independently

## Overview

Vigolium's native scan pipeline consists of multiple phases that run sequentially. You can run the full pipeline, isolate a single phase with `--only`, or skip specific phases with `--skip`. This guide walks through each phase and how to run them independently.

## The Full Pipeline

When you run a scan, the enabled phases execute in this order (the source of
truth is `BuildNativeScanPlan` in `internal/runner/native_plan.go`):

1. **Heuristics check** (`heuristics-check`) - fetch each target's root page and classify it (blank vs content, JSON/XML API; with `scanning_strategy.heuristics_check: advanced` also SPA detection and link counting) to decide whether spidering that target is worthwhile. It does not fingerprint technologies. On by default (`basic`); turned off by `--skip heuristics-check` and by any `--only` that does not list it
2. **Port Sweep** (`port-sweep`) - find extra web services on alternate ports of the CLI target hosts and add them to the target set. Only with `--intensity deep`, `--follow-subdomains`, or `--only port-sweep`; turned off by `--skip port-sweep` and by any `--only` that does not list it. Its HTTP confirm requests go through `--proxy`; the TCP connect that finds open ports cannot and always dials the host directly
3. **External Harvest** (`external-harvest`) - gather URLs about the target from third-party archives (Wayback Machine, CT logs); never contacts the target
4. **Harvest probe** (`harvest-probe`) - check the harvested URLs against the live target so later phases scan only the ones that still answer (see [External Harvest](#external-harvest)). Runs only when external-harvest ran AND a later enabled phase reaches the target anyway; `vigolium run external-harvest` alone never schedules it
5. **Spidering** (`spidering`) - browser-based crawling to discover dynamic content
6. **Probe** (`probe`) - one request per target, passive modules only, no content discovery (an httpx-style host sweep). Opt-in: runs only with `--only probe` / `vigolium run probe`
7. **Discovery / Ingestion** (`discovery`) - parse inputs and perform content discovery
8. **Targeted re-spider** (`targeted-respider`) - re-crawl the rich/SPA routes discovery surfaced after the first browser crawl. Runs only when spidering, discovery, and dynamic assessment are all enabled (and `discovery.respider` allows it)
9. **Seed** (`seed`) - when discovery/ingestion is skipped (for example `--only dynamic-assessment`), store the CLI targets as records so the assessment phases have something to scan. Not run under scan-on-receive
10. **Param mining** (`param-mining`) - discover hidden parameters (Arjun-style) on this scan's dynamic endpoints and store each one as a record, so the assessment tests it too (see [Param Mining](#param-mining)). On at `--intensity deep` or with `--param-mining`; never without dynamic assessment
11. **DynamicAssessment** (`dynamic-assessment`) - run active, passive, and extension modules
12. **Known Issue Scan** (`known-issue-scan`) - run Nuclei plus native in-process secret detection

Every step above is a name in the phase vocabulary, so each `phase.started` /
`phase.finished` id can be looked up in `vigolium strategy -j` (`phases[]`).
`harvest-probe`, `targeted-respider`, `param-mining` and `seed` are **internal**: the plan schedules them on its
own gates, so `--only` rejects them. `--skip harvest-probe`, `--skip targeted-respider` and `--skip param-mining` are accepted
(external-harvest, spidering and the assessment still run); `seed` cannot be skipped. `preflight` is also reserved as
an internal, skippable name for the target reachability check; `--skip preflight`
is accepted today and has no effect until that check lands.

A full scan with all phases enabled:

```bash
vigolium scan -t https://example.com --strategy deep
```

## Running a Single Phase

Use `vigolium run <phase>` or `vigolium scan --only <phase>` to execute one phase in isolation.

### Discovery

Discovers new endpoints through wordlist-based fuzzing and content probing:

```bash
vigolium run discovery -t https://example.com
```

Equivalent to:

```bash
vigolium scan -t https://example.com --only discovery
```

Tune discovery with additional flags:

```bash
vigolium run discovery -t https://example.com \
  --discover-max-time 30m \
  -c 100 \
  --rate-limit 200
```

### Spidering

Crawls the target using a headless browser to discover pages, forms, and JavaScript-rendered content:

```bash
vigolium run spidering -t https://example.com
```

Control the browser engine, time budget and what the crawl may change:

```bash
vigolium run spidering -t https://example.com \
  -E chromium \
  --spider-max-time 20m \
  --no-forms
```

The crawler drives one browser (`-b`/`--browsers` above 1 is clamped to 1).
Under the phase header it prints the resolved interaction `Policy:` and the
`Browser security:` posture (see [Browser policy](browser-policy.md)). Its
completion line is built from capture receipts: when records were lost it says
`run incomplete` instead of reporting the stored count as the whole crawl, and
per-target notes call out authentication that could not be applied, credential
headers withheld from out-of-scope hosts, and readiness conditions that never
met.

The alias `spitolas` also works:

```bash
vigolium run spitolas -t https://example.com
```

### External Harvest

Pulls endpoints from external intelligence sources (Wayback Machine, certificate transparency logs).
It never contacts the target: each harvested URL is stored as a request-only record
(`source=harvest`, no response).
URLs are normalized (tracking params and static assets dropped, `.js`/`.map` kept) and sampled by
path shape before they are stored — see `external_harvester.per_shape`, `max_urls` and `cdx` in
[configuration](../configuration.md#external_harvester). A Wayback index that hits `cdx.max_rows`
is reported as the `cdx_max_rows` phase limit:

```bash
vigolium run external-harvest -t https://example.com
```

When a later phase will reach the target (`--external-harvest` on a normal scan,
`--only harvest,dast`, …), the **harvest probe** step runs right after the harvest,
so archive history is not fuzzed:

1. One liveness request per origin (`scheme://host:port`), to a random path. An
   origin with no HTTP answer has all of its harvested URLs dropped unfetched.
2. One GET per harvested URL on a live origin, through the shared requester (scan
   session, rate limit, per-host limiter). Redirects are recorded on the record,
   not followed.
3. `404`/`410` answers are dropped, as are soft-404s: on an origin that answers
   unknown paths with a `2xx` page or a `3xx` redirect, a response with the same
   status, media type and size (or redirect destination) as the random path's is
   treated as "not found". Origins that answer unknown paths with `404` are judged
   by status alone; `401`/`403`/`5xx` are always kept.

Survivors keep `source=harvest` and get their response filled in. Dropped URLs'
request-only stubs are deleted, so no later phase scans them (a record another
phase already fetched is never touched). The tallies land on the phase outcome
(`scan.phase_outcomes[].counts`): `stubs`, `hosts`, `hosts_dead`, `probed`, `kept`,
`dropped_dead_host`, `dropped_not_found`, `dropped_soft_404`, `dropped_failed`,
`unprobed`, `deleted`, `write_failed`. Turn the step off with `--skip harvest-probe`
for one run, or `external_harvester.probe: false` in the config, to let the later
phases fetch every harvested URL themselves.

### Known Issue Scan

Runs template-based scanning (Nuclei templates) against ingested endpoints:

```bash
vigolium run known-issue-scan -t https://example.com
```

Filter templates by severity or tags:

```bash
vigolium run known-issue-scan -t https://example.com \
  --known-issue-scan-severities critical,high \
  --known-issue-scan-tags cve,rce
```

### Param Mining

Finds parameters an endpoint reads although no recorded request carries them
(`debug=`, `callback=`, `admin=`) and hands them to dynamic assessment. It is
internal (no `--only`), and runs right before the assessment when either:

- `--intensity deep` (and no `--only`), or
- `--param-mining` (any intensity, also with `--only dast`).

`--param-mining=false` or `--skip param-mining` (aliases `params`, `arjun`,
`param-miner`) turns it off, and it never runs without dynamic assessment.

```bash
vigolium scan -t https://example.com --intensity deep        # mining included
vigolium scan -t https://example.com --param-mining          # balanced scan + mining
vigolium run dast -t https://example.com --param-mining      # rescan stored records with mining first
```

Endpoints come from the records the assessment will read: 2xx, GET or POST,
dynamic content (HTML, JSON, XML, text; no static assets), one per method and
path, the top `max_endpoints_per_host` (50) per origin by `risk_score`. Each is
mined by the same engine as `vigolium kit param-mine`: two baselines with a random
parameter (an endpoint whose baselines disagree is skipped as `unstable`), names
in chunks sized to the transport, bisection to single names, and two fresh-value
confirmations. The wordlist puts the host's own names first (from jstangle facts
and the host's recorded traffic), then `dynamic-assessment.param_mining.wordlist`,
then the built-in list (`vigolium kit wordlist params`). Every request goes
through the scan's requester (session, rate limit, host limiter);
`max_requests_per_endpoint` (60) bounds each endpoint, and a burst of 403/429/WAF
answers stops it.

Each confirmed parameter becomes an `http_records` row with `source:
param-mining`, a remark `param-mining:name=<n>;signal=<reflect|status|header|length|body>`,
and `hidden: true` on that parameter. `phase.finished` counts: `candidates`,
`endpoints`, `mined`, `unstable`, `blocked`, `budget_exhausted`, `failed`,
`names_tested`, `params_found`, `records_written`, `write_failed`.

```yaml
dynamic-assessment:
  param_mining:
    max_endpoints_per_host: 50
    max_requests_per_endpoint: 60
    max_words: 0          # 0 = no cap on the merged wordlist
    wordlist: ""          # extra names file, tried before the built-in list
    concurrency: 0        # endpoints at once; 0 = min(-c, 10)
```

### DynamicAssessment

Runs active and passive vulnerability scanning modules. This is the core scanning phase. CLI aliases: `audit`, `dast`, `assessment`.

```bash
vigolium run dynamic-assessment -t https://example.com
```

Select specific modules or tags:

```bash
vigolium run dynamic-assessment -t https://example.com -m xss -m sqli
vigolium run dast -t https://example.com --module-tag injection
```

### Extension

Runs only custom JavaScript or YAML extensions:

```bash
vigolium run extension -t https://example.com --ext ./my-checks.js
```

## Skipping Phases

Use `--skip` to disable specific phases while keeping the rest of the pipeline:

```bash
# Run everything except spidering
vigolium scan -t https://example.com --discover --skip spidering

# Skip both spidering and known-issue-scan
vigolium scan -t https://example.com --discover --skip spidering --skip known-issue-scan
```

Note: `--only` and `--skip` cannot be used together.

## Phase Aliases

Every phase answers to several spellings. They work identically with `--only`, `--skip`, the `vigolium run <phase>` argument, the per-phase pace qualifiers (`--rate-limit crawl=20`) and the REST API's `only`/`skip` fields. Names are trimmed and lowercased first, so `--skip Spider` and `--skip ' spider'` both resolve.

| Phase | Also accepts |
|-------|--------------|
| `ingestion` | `ingest`, `ingesting` |
| `probe` | `probing`, `httpx`, `alive`, `sweep` |
| `discovery` | `discover`, `discovering`, `deparos` |
| `external-harvest` | `harvest`, `harvesting`, `external-harvester`, `external_harvester` |
| `spidering` | `spider`, `spitolas`, `crawl`, `crawling`, `crawler` |
| `known-issue-scan` | `cve`, `kis`, `known-issue`, `known-issues` |
| `dynamic-assessment` | `dast`, `audit`, `assessment`, `assess` |
| `extension` | `ext`, `extensions` |
| `heuristics-check` | `heuristics`, `heuristic` |
| `port-sweep` | `ports`, `portsweep`, `port-scan` |
| `harvest-probe` (internal: `--skip` only) | `harvest-check` |
| `targeted-respider` (internal: `--skip` only) | `respider`, `re-spider` |
| `param-mining` (internal: `--skip` only) | `params`, `arjun`, `param-miner` |
| `seed` (internal: neither) | |
| `preflight` (internal: `--skip` only, reserved) | |

`--skip extension` turns extensions off for the run, even when the config or `--ext` enabled them; the built-in modules still run. `--skip heuristics-check` is the same as `--skip-heuristics`.

`strategy -j` reports each phase with `skippable`, `internal` and `only_accepted`, so a caller can tell which list a name belongs to without parsing help text.

One exception applies to the positional form only: `vigolium run audit` is rejected as ambiguous, because it reads as `vigolium agent audit` (the AI source-code audit) rather than the native module-scanning phase. Use `vigolium run dynamic-assessment` (or `dast`). `--only audit` and `--skip audit` are unaffected.

### `run <phase>` and `scan --only <phase>` are the same thing

`vigolium run discover` is not a lighter variant of `vigolium scan --only discovery` — it is literally the same code path, so the two behave identically in every respect.

What *does* differ is running a phase on its own versus running it inside a full pipeline. The clearest case is discovery's FUZZ brute-force: it is enabled whenever the active `--only` set contains `discovery`, and disabled when discovery runs as one phase of a balanced or lite full scan. The Discovery phase header prints which applies:

```
◆ Fuzzing: enabled — fuzz.txt (5369) (embedded default), appends /FUZZ [discovery-only run]
◆ Fuzzing: disabled — off on balanced/lite full scans (enable via `run discover`, --intensity deep, or --discovery-wordlist)
```

### Turning discovery fuzzing off

`--no-discovery-fuzz` (alias `--no-fuzz`) disables the `/FUZZ` brute-force outright. It is checked before every rule that would switch fuzzing on, so it wins over `--intensity deep`, over a discovery-only run, and over the low-yield auto-enable:

```bash
vigolium run discover -T hosts.txt --no-fuzz            # content discovery without the 5369-word brute
vigolium scan -t https://example.com --intensity deep --no-fuzz
```

The rest of discovery is untouched — link extraction, robots.txt, JS parsing (jstangle, Next.js/Angular/CRA manifests, source maps), response-word harvesting into the observed wordlists, form submission, and the short `dir-short.txt`/`file-short.txt` dictionaries all still run. `--intensity deep` still loads the large dictionaries (`discovery.wordlists.tier`); only the `/FUZZ` task is removed.

Passing `--no-discovery-fuzz` together with `--discovery-wordlist` is an error rather than a precedence rule — the two state opposite intents, and the outcomes differ by thousands of requests per host.

## Chaining Phases Manually

You can chain independent phase runs to build a custom pipeline. Each phase stores its results in the database, so subsequent phases pick up where the previous one left off:

```bash
# Step 1: Discover endpoints
vigolium run discovery -t https://example.com

# Step 2: Dynamic-assessment against the discovered endpoints
vigolium run dynamic-assessment -t https://example.com

# Step 3: Run custom extensions against results
vigolium run extension -t https://example.com --ext ./custom-check.js
```

## Tuning Per-Phase Performance

Override concurrency and rate limits for individual phases using the config file (`vigolium-configs.yaml`):

```yaml
scanning_pace:
  concurrency: 50
  rate_limit: 100

  discovery:
    concurrency: 100
    duration_factor: 1.0

  spidering:
    max_duration: 20m

  dynamic-assessment:
    parallel_passive: true
```

CLI flags (`-c`, `--rate-limit`) always take precedence over config values.

## Controlling Scope

Scope filtering applies across all phases. Use `--scope-origin` to control host matching:

```bash
# Strict: exact host match only
vigolium run discovery -t https://api.example.com --scope-origin strict

# Balanced: same eTLD+1 (*.example.com)
vigolium run discovery -t https://api.example.com --scope-origin balanced

# Relaxed (default): host contains target keyword
vigolium run discovery -t https://api.example.com --scope-origin relaxed
```

## Adding Authentication

All phases respect authentication headers. Pass them with `-H`:

```bash
vigolium run dynamic-assessment -t https://api.example.com \
  -H 'Authorization: Bearer eyJhbGciOi...' \
  -H 'Cookie: session=abc123'
```

For multi-session testing (e.g., IDOR detection), use session configs:

```bash
vigolium run dynamic-assessment -t https://api.example.com \
  --auth-file sessions.yaml
```
