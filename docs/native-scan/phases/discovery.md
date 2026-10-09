# Deparos — Modern Adaptive Content Discovery

Deparos is an intelligent content discovery engine that performs directory enumeration, directory fuzzing, and endpoint discovery against web applications. It goes beyond static wordlist brute-forcing by learning from every response — adapting its strategy, growing its wordlists dynamically, and filtering false positives through fingerprint-based soft-404 detection.

## How It Works

```
Target URL
  │
  ▼
┌──────────────────────────────────────────────────────┐
│  Initialization                                      │
│  1. Probe target, extract host components            │
│  2. Fetch robots.txt, then its sitemaps              │
│  3. Learn baseline fingerprints (3-sample soft-404)  │
│  4. Load prior session data (if resuming)            │
│  5. Generate initial tasks from wordlists + observed │
└──────────────────┬───────────────────────────────────┘
                   ▼
┌──────────────────────────────────────────────────────┐
│  Priority Queue                                      │
│  ┌────┬────┬────┬────┬─────┬──────┬──────┬────────┐ │
│  │ P0 │ P1 │ P2 │ P4 │ P5-6 │ P7   │ P8-11│ P12 │ │
│  │Spdr│JSReq│Obs │Obs │Short │ExtVar│Long  │Fuzz │ │
│  │ JS │Name │File│Path│Words │Numeric│Words │     │ │
│  └────┴────┴────┴────┴─────┴──────┴──────┴────────┘ │
└──────────────────┬───────────────────────────────────┘
                   ▼
┌──────────────────────────────────────────────────────┐
│  Payload Coordinator                                 │
│  Expander pulls tasks → Expand() yields payloads     │
│  N workers execute payloads concurrently             │
│                                                      │
│  For each response:                                  │
│    Fingerprint check (soft-404?) ──→ discard         │
│    WAF detection ──→ track/backoff                   │
│    Real discovery ──→ callbacks                      │
└──────────────────┬───────────────────────────────────┘
                   ▼
┌──────────────────────────────────────────────────────┐
│  Discovery Callbacks                                 │
│  OnDirectoryDiscovered():                            │
│    • Learn new fingerprints for directory             │
│    • Create recursive tasks (wordlists + observed)   │
│    • Extract breadcrumb directories                  │
│  OnFileDiscovered():                                 │
│    • Extract extension → trigger extension tasks     │
│    • Numeric segment → optional ±10 fuzz variations  │
│    • Queue extension variant probes (.bak, .old, …)  │
└──────────────────┬───────────────────────────────────┘
                   ▼
        ┌──── loop back to Priority Queue ────┐
        │  (new tasks from discoveries)       │
        └─────────────────────────────────────┘
```

## What Makes It Adaptive

### 1. Fingerprint-Based Soft-404 Detection

Before scanning, the engine requests 3 random non-existent paths and extracts response attributes (status code, content-type, headers, body hash, content-length ranges). Only attributes **stable across all 3 samples** become the baseline signature. During scanning, responses matching this signature are discarded as false positives.

When an unknown response pattern appears, a 4-strategy wildcard validation (prefix, suffix, extension, middle) confirms whether the discovery is real or a new soft-404 variant — and learns the new pattern.

### 2. Observed Collection System

Four data pools grow continuously during the scan:

| Pool | Source | Priority |
|------|--------|----------|
| Observed Names | Spider links, JS parsing, response body tokenization | P1-P3 depending on extension source |
| Observed Files | Complete filenames from discoveries | P2 |
| Observed Extensions | File extensions confirmed from application evidence | Combined with observed/short/long file tasks at P3, P6, and P11 |
| Observed Paths | Full paths from URLs | P4 |

Every newly discovered directory is probed with ALL observed values as high-priority tasks. When a new extension is found for the first time, it triggers tasks across ALL known directories.

### 3. JavaScript Intelligence

Two layers of JS analysis feed the discovery graph:

- **JSTangle** uses a shared, memory-bounded worker pool. It emits typed HTTP
  templates plus JavaScript chunks/workers/source maps, GraphQL operations,
  WebSocket/SSE metadata, client routes, and browser-side flow evidence.
- **Spider/LinkFinder extractors** retain a cheap URL-string fallback for code
  that cannot or should not enter full AST analysis.

Request facts keep their source script, method, body, confidence, and source
span. High-confidence facts use exact replay. Medium-confidence facts are only
replayed when `replay_mode: conservative`; low-confidence strings remain hints.
Sensitive or browser-controlled headers are never copied into replay traffic.

Client routes are seeded by their full path: nested Angular/Vue `children`
are joined onto their parents (`/admin/reports/:id` → `/admin/reports/1`).
Path-shaped literals that no request or route consumed (`{profile:
"/api/v2/profile"}`, `const EXPORT = "/api/v2/export"`) arrive as
low-confidence `pathLiteral` hints: API-looking paths, or ones bound to a
`url`/`path`/`endpoint`/`api`/`route`/`href` key, are trusted seeds and API
paths are fetched; the rest join the observed-path pool. Request facts also
carry the credential source (`auth.source`, for example `localStorage:jwt`),
never the credential.

When a script holds more endpoints than the request cap, the analysis is
`partial` with reason `request_cap` and a per-kind `truncated` count, instead
of a silently shortened list.

Every in-scope request template survives the crawl, not only the ones whose
replay was judged to exist. After each target, a template that did not become
a discovery node is stored as an `http_records` row with `source=jstangle`: the
rendered method, URL, safe headers and body, plus the response when it was
replayed. Its remarks say what happened to it:

| Remark | Meaning |
|---|---|
| `jstangle:<outcome>` | `replayed_found`, `replayed_not_found`, `withheld_policy`, `withheld_confidence`, `withheld_flush_cap`, `deduped`, `unresolvable` |
| `jstangle:reason=<r>` | detail, for example `method:POST`, `graphql-mutation`, `medium`, `unreplayed` |
| `jstangle:confidence=<c>`, `jstangle:extractor=<e>` | the fact's provenance |
| `jstangle:src=<script>#L<line>` | where the call is in the bundle |
| `jstangle:auth=<kind>:<source>` | the credential source, for example `bearer:localStorage:jwt` |
| `jstangle:method=unresolved` | the method was templated; the row falls back to GET |

Found templates keep their existing row and gain the same remarks. Out-of-scope
templates and low-confidence hints are never stored as rows. Only found
templates and not-found replays that answered 400, 405, 415 or 422 (the route
exists and wants other input) are handed to later phases; 404s and withheld
templates are stored only, so persisting never sends a request `replay_safety`
withheld. Each row carries its full fact as a `jstangle-fact` analysis artifact,
and each JS asset gets one `jstangle-facts` artifact with its non-request facts
(client routes with `fullPath`, GraphQL operations, WebSocket/SSE endpoints,
asset references, browser security flows, path literals and low-confidence
request hints). At most 2000 rows are stored per target; past that the run
reports the `js_template_persist_cap` limit. The knobs are
`discovery.jstangle.persist_unreplayed` (store never-sent templates, default
true), `persist_not_found_emit_statuses` and `max_persisted_js_templates`.

Asset references form a bounded recursive graph, so lazy chunks, workers, and
service workers are fetched and analyzed once. Source maps are fetched under the
normal scope/auth/rate policy; recovered sources are retained as immutable scan
artifacts. WebSocket/SSE handshakes are opt-in and never pass through ordinary
HTTP variant generation.

Large input degrades visibly: transformed output is dropped first, then a
bounded lexical endpoint/asset pass is used. Hard-limit input is rejected with a
diagnostic. A summary reports worker jobs, cache hits, extracted fact confidence,
fallbacks, and worker restarts when discovery stops.

### 4. Sitemaps

After robots.txt, discovery reads the sitemaps it names on `Sitemap:` lines.
When it names none, it probes `/sitemap.xml` and `/sitemap_index.xml`. The
parser streams `<urlset>`, `<sitemapindex>`, gzip (recognised by the `1f8b`
magic, so a `.gz` URL the transport already decoded still works) and
plain-text sitemaps. Each document is capped at 50 MiB decompressed and 50,000
entries, and a gzip stream that expands more than 100x is treated as a bomb and
abandoned. Index children are followed to depth 2, with at most 16 per index
and 32 documents per target. Every `<loc>` is scope-checked.

- Every in-scope `<loc>` path feeds the observed-path pool (trusted frequency).
- A sample becomes spider links (`Sitemap` source), so each sampled page is
  fetched and recorded. URLs are grouped by host and path shape
  (`pkg/httpmsg/pathshape`), so `/product/41` and
  `/product/42` are one shape. The sample takes `per_shape` URLs per shape
  (default 3) round-robin across shapes, up to `max_urls` per target
  (default 2000).
- URLs a budget drops are counted. When any are dropped, the discovery phase
  notes the `sitemap_cap` limit.

```yaml
discovery:
  sitemap:
    enabled: true       # default
    max_urls: 2000      # sampled URLs spidered per target (0 = 2000)
    per_shape: 3        # sampled URLs per host + path shape (0 = 3)
    follow_index: true  # fetch <sitemapindex> children
```

Robots-named sitemaps are no longer spidered as opaque files. When the
sitemap source is disabled, they are spidered as before.

### 5. Dynamic Wordlist Growth

Response bodies are tokenized (content-type-aware for HTML, JSON, JS, CSS) to extract candidate words. These feed into the observed name pool and are replayed against every directory.

### 6. Recursive Directory Expansion

When a file is found at `/a/b/c/file.txt`, the engine extracts `/a/`, `/a/b/`, `/a/b/c/` as directories to test. Each new directory triggers its own full task set (wordlists + observed + modules).

## Task Types

| Task | Priority | Description |
|------|----------|-------------|
| Spider, JS fetch, form submission | 0 | Highest-confidence URLs and assets from browser/link extraction |
| JS extracted requests | 1 | Typed requests recovered from JavaScript |
| Observed filenames without extension | 1 | Server-leaked names replayed per directory |
| Observed files/directories/literal filenames | 2 | Complete observed resources and directories |
| Observed names × observed extensions | 3 | Confirmed application names combined with confirmed extensions |
| Observed paths | 4 | Full paths recovered from URLs |
| Short files without extension | 5 | Common short filename dictionary |
| Short directories/files with extensions | 6 | Common directory names and short filename combinations |
| Extension variants | 7 | Backup/alternate extensions (`.bak`, `.old`, `.zip`, `.tar.gz`) |
| Numeric fuzz | 7 | ±10 variants of numeric path segments when `enable_numeric_fuzzing` is enabled (off by default) |
| Long files without extension | 8 | Extended filename dictionary |
| Long directories/files with configured extensions | 9 | Extended wordlist combinations |
| Malformed-path probe | 10 | Detects path-normalization and routing behavior |
| Long files with observed extensions | 11 | Lowest-priority long-wordlist extension combinations |
| FUZZ | 12 | Template-based fuzzing (`FUZZ` marker replacement) |

## Scope enforcement

Content discovery runs its own HTTP client, so the executor's scope check — which
runs on records that have already been fetched — could only ever discard an
out-of-scope response *after* contacting the host. An explicit exclusion is a
request not to contact it, so it is enforced at the engine's egress instead:

- `scope.host.exclude` and `scope.path.exclude` are compiled into a predicate the
  engine consults **before every request leaves**. A refused request is never
  sent, never retried, and never counted toward the consecutive-network-error
  budget that can abort a crawl.
- The same predicate excludes the URL from the spider queue, so an excluded link
  is not even scheduled — in every scope mode, including the default `any`.
- Only the **exclude** lists are enforced here. `scope.host.include` and the CLI
  origin mode are not: narrowing discovery to an include list is not what an
  include list means. How wide the crawl goes is still `discovery.scope_mode`'s
  job (`any` / `subdomain` / `exact`).

The phase's `requests_sent` figure on `phase.progress` and `phase.finished` counts
the engine's own physical attempts, retries included. Before, the phase reported
the shared requester's delta — which a crawl barely touches — so a discovery run
that sent tens of thousands of requests reported roughly zero.

## Deduplication

Multiple layers prevent redundant work:

- **Task-level**: FNV-1a hash prevents duplicate task enqueueing
- **Request-level**: Cache prevents sending the same HTTP request twice
- **URL-level**: DiskSet tracks processed URLs
- **Body-level**: Hash prevents re-analyzing identical responses with JSTangle
- **Directory/file trackers**: Prevent re-processing the same discovery

### Stored-record cleanup

After the phase, three passes prune the stored records: the status-retention
policy (4xx tiers), reflected-URL collapse by normalized body hash, and a
shape-based soft-dedup backstop. Two properties bound what they can remove:

- **Evidence is never deleted.** A pass skips any record referenced by a finding
  (`finding_records`) or by an analysis artifact, and leaves the link intact. The
  feedback line reports the spared count as `kept N referenced by findings`, so a
  deletion count lower than the candidate count is expected, not a failure.
- **Only `source=deparos` records are touched.** JS-derived (`jstangle`),
  form (`html-form`) and API-spec (`api-spec`) records, including stored 404
  stubs of JS endpoints, are never pruned.
- **Grouping is per origin.** Records are grouped by `(hostname, scheme, port, …)`,
  so `http://h/x`, `https://h/x`, and `https://h:8443/x` each keep their own
  representative rather than collapsing into one.

Cleanup is **project-scoped, not scan-scoped**: it runs over every discovery
record in the project, including records stored by earlier scans. The evidence
guarantee above is what keeps a later scan from pruning an earlier scan's proof.

## Discovery Modules

The only compiled-in discovery module is `wildcard`, which suppresses work under wildcard/catch-all paths. Additional modules are user-defined in YAML through `module-definitions.custom`; they can match paths, segments, filenames, extensions, or globs and then stop recursion, skip default logic, enqueue wordlist tasks, or block matching tasks. Names such as `backup`, `api`, or `static` are examples of custom policy, not guaranteed built-ins.

## Supporting Systems

| Component | Purpose |
|-----------|---------|
| **WAF Detection** | Identifies Cloudflare, Akamai, AWS WAF, F5, Imperva, Sucuri, ModSecurity. Tracks consecutive blocks for backoff/early exit |
| **Scope Enforcement** | Three modes: `any` (no check), `subdomain` (same eTLD+1), `exact` (same host). Checked on every discovery and redirect |
| **Case Sensitivity Detection** | Auto-detected on first file discovery by re-requesting with altered casing |
| **Storage** | SQLite-backed sitemap with semantic dedup (FNV-1a-64). Supports session comparison for differential scanning across runs |

## Integration with Vigolium

Deparos runs as an input source (`DeparosDiscoverySource`) in the scanning pipeline. Each discovery is converted to an `httpmsg.HttpRequestResponse` and fed to the executor as a work item — where it flows through active and passive vulnerability scanning modules.

```
DeparosDiscoverySource.Next()
  → per target: Engine.Start(), then wait for the queues to drain
                or the target's budget to expire
  → read that target's temporary sitemap
  → dedup in memory, convert to httpmsg.HttpRequestResponse
  → persist the batch (optional)
  → emit as WorkItems → Executor → Scanner Modules
  → next target
```

Discoveries are collected **per target and emitted as a batch**, not streamed as
each one lands: the engine has to finish a target before its sitemap can be read
and deduplicated. Each target gets its own wall-clock budget
(`--discover-max-time`, else `scanning_pace.discovery.max_duration`, else 1h);
exhausting it ends that target and moves to the next, and whatever that target
already found is still imported.
