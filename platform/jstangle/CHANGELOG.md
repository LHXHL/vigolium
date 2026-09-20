# Changelog

All notable changes to `jstangle` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-09-20

Large bundles are recovered instead of rejected. A script dense enough to
exceed the AST node budget previously returned zero endpoints, and the stage
written to handle exactly that case — `bundleModuleScan` — was skipped, because
it was ordered behind the stage that rejected the input.

### Added

- Recovery path for an AST budget rejection: exceeding `maxAstNodes` in the
  `parse` stage now routes the input to the per-module bundle scan rather than
  ending the run. A tree too dense to traverse whole is the strongest available
  signal that the input is a bundle and should be analyzed per module. The run
  reports `partial` with a new `ast_budget_recovered_by_module_scan` diagnostic.
  A syntactically broken input (`parse_unrecoverable`), an exhausted deadline,
  and a dense *non-bundle* all still fail hard — this is not a budget bypass.
- `maxBundleModules` is accepted as a worker limit, so a host can bound the
  per-module scan instead of being stuck with the default.
- `moduleBanner()` is exported: the section header that separates modules in the
  assembled beautified document is now part of the contract, so a consumer can
  split that document back into per-module files.

### Changed

- `maxBundleModules` default raised from 64 to 512. A CRA/Next build routinely
  emits several hundred to a few thousand modules, so 64 truncated the scan long
  before the deadline did.
- `scanBundleModules` orders modules by endpoint likelihood (request-issuing
  markers first, then first-party paths) before applying the cap, so a truncated
  scan loses the vendor tail rather than application code.
- Each per-module sub-scan gets its own share of the node budget. It previously
  inherited the full `maxAstNodes`, letting one pathological module exhaust the
  whole deadline before the rest of the bundle was looked at.
- `bundleModuleScan`'s enablement moved from the stage gate into the stage body.
  Gates are evaluated when the plan is built, before any stage has run, so a
  gate could never observe a parse failure that happens later.

### Fixed

- `BeautifyResult.modulePaths` now follows the assembled document's order
  (entry module first). It previously reported the unsorted order while
  `content` was sorted, so the two could disagree and a consumer walking both in
  lockstep would mis-associate paths with sections.

## [0.1.1] - 2026-07-11

First release under the `jstangle` name — a rename of the previous `jsscan`
helper (see [0.1.0]) plus a substantial round of enhancements. `jstangle` is the
JavaScript intelligence engine inside Vigolium: it deobfuscates, beautifies, and
AST-parses JavaScript bundles to surface hidden endpoints, request shapes, and
other useful information.

### Added

- Deobfuscation + beautification pipeline (webcrack-backed, loaded lazily) with
  selectable rewrite levels (`strict` | `standard` (default) | `aggressive`).
- Typed analysis-result envelope with per-record confidence and provenance, plus
  contained artifacts for large transformed/beautified documents.
- Typed record families: `httpRequest`, `domFlow`, `assetReference`,
  `graphqlOperation`, `websocket`, `eventSource`, `clientRoute`, and
  `browserSecurityFlow`.
- Analysis profiles so each caller runs only the stages it consumes:
  `endpoints`, `dom-security`, `beautify`, `discovery`, `discovery-lite`,
  `full`, and `inspect`.
- CLI now accepts JavaScript from a file path, raw JS as the first positional
  argument, or piped stdin.
- `--capabilities` machine-readable build/capability contract and a persistent
  length-framed `--worker` transport for the Go scanner.
- Version tracking single-sourced from `package.json` (compiled into the binary
  as the reported `toolVersion` / `--version`).
- Standalone, publishable CLI package `@vigolium/jstangle` (`bun run npm-publish`).

### Changed

- Renamed the project and helper binary from `jsscan` to `jstangle`.
- Relicensed under the MIT License.

## [0.1.0]

Previous release, shipped under the name `jsscan` — the endpoint/request
extraction helper that preceded the `jstangle` rename and enhancements.

[0.2.0]: https://github.com/vigolium/jstangle/releases/tag/v0.2.0
[0.1.1]: https://github.com/vigolium/jstangle/releases/tag/v0.1.1
[0.1.0]: https://github.com/vigolium/jstangle/releases/tag/v0.1.0
