# Building & Testing

Vigolium is a Go project (module `github.com/vigolium/vigolium`, **Go 1.27+**).
All build and test workflows go through the `Makefile` — it injects version
metadata and manages embedded assets that a bare `go build` would skip.

> **Always build with `make`.** Never run `go build` to `./vigolium` or an
> ad-hoc path: it bypasses version injection (`-ldflags`) and can leave a stale
> binary in the working tree. Use `make build` (→ `bin/vigolium`) or
> `make install` (→ `$GOPATH/bin`).

## Prerequisites

| Tool | Why |
|------|-----|
| Go 1.27+ | Language toolchain (`go-version` is pinned in `go.mod`) |
| [Bun](https://bun.sh) | Compiles the JS analysis engine embedded via `//go:embed` (`make ensure-jstangle`) |
| Docker | Only for e2e/canary tests against vulnerable apps |
| `golangci-lint` v2 | Linting (`make lint`); installed automatically by some targets |

The **jstangle** binary is generated, not committed. A fresh checkout will not
compile until it exists, so run `make ensure-jstangle` once (or just `make build`,
which depends on it transitively). The **vigolium-audit** harness binary is
managed the same way via `make ensure-audit`.

### Embedded helpers are zstd-compressed

Both helpers are embedded compressed, not raw. The staging targets run
`internal/tools/blobpack`, which writes `<blob>.zst` plus a `<blob>.pin` file
recording the sha256, size and platform of the **uncompressed** executable
(and, for jstangle, its source fingerprint). The `go:embed` directives take
those two files:

| Helper | Raw blob (staging input) | Embedded |
|---|---|---|
| jstangle | `internal/resources/deparos/jstangle/jstangle-<os>-<arch>[.exe]` | same path + `.zst` / `.pin` |
| vigolium-audit | `platform/vigolium-audit/build/dist/vigolium-audit-<os>-<x64\|arm64>` | `pkg/audit/bin/_bin/vigolium-audit.zst` / `.pin` |

- On first use the extractor decompresses into the existing cache
  (`~/.cache/jstangle/`, `<user-cache>/vigolium/vigolium-audit-<sha12>/`) and
  checks the result against the pin. A mismatch is a hard error naming the
  expected and actual sha256, and nothing is installed. The pinned hash is the
  uncompressed hash, so cache keys are unchanged.
- Packing is content-addressed: re-running it on an unchanged blob only
  re-hashes it. `make build`, `make ensure-jstangle` and `make ensure-audit`
  pack the host helper. `make pack-jstangle [JSTANGLE_TARGET=<os>-<arch>]`
  packs explicitly, and `build/scripts/stage-audit-blob.sh <goos> <goarch>`
  stages audit for one target. Both refuse a blob whose executable header is
  for another platform.
- The jstangle release gates still read the raw blobs (`--capabilities`, the
  fingerprint byte search). `ensure-jstangle-dist` also requires every `.pin`
  to record the current fingerprint, which is what keeps it visible to the
  npm gate in the vigolium binary now that the blob bytes are compressed.
- Never leave a raw `vigolium-audit` in `pkg/audit/bin/_bin/`. `go:embed
  all:_bin` would embed it uncompressed, and `TestEmbedCarriesOnlyCompressedBlob`
  fails if you do. `make ensure-audit` repacks a leftover one.

Compression ratios on darwin/arm64 were 3.05x for jstangle and 3.44x for
vigolium-audit, which brought `bin/vigolium` from about 310 MB to about 220 MB.
First-use decompression adds well under a second.

### Opt-in lazy vigolium-audit (`-tags audit_external`)

`make build-audit-external` builds `bin/vigolium-audit-external` with no
vigolium-audit embedded. The binary downloads the helper on first use instead.
Default builds keep embedding, because no CDN hosts the helpers yet.

- `make audit-external-pins` runs `stage-audit-blob.sh --pins`, which
  generates the gitignored `pkg/audit/bin/pins_gen.go` (`os_arch` → sha256,
  size and platform) from the dist blobs. It also writes the upload assets
  `build/dist-helpers/vigolium-audit_<sha12>_<os>_<arch>.zst`.
- The download URL is `$VIGOLIUM_AUDIT_BASE_URL/vigolium-audit_<sha12>_<os>_<arch>.zst`.
  The link-time default comes from `make build-audit-external AUDIT_EXTERNAL_BASE_URL=https://…`.
  The URL must be https, redirects to anything else are refused, and the
  payload must hash to the pin before it is installed into the same cache
  directory an embedded build uses.
- `VIGOLIUM_AUDIT_BINARY=/path/to/vigolium-audit` bypasses the embedded or
  downloaded helper in any build, which suits air-gapped hosts and local
  development.
- `vigolium doctor` reports the helper's source, pinned sha256, cache path and
  whether it is installed, without downloading anything.
  `vigolium doctor --fix --only vigolium-audit` prefetches it. When the helper
  cannot be fetched, `Path` returns `ErrHelperUnavailable` with a remediation
  hint.

## Build targets

```bash
make build              # → bin/vigolium (+ installs to $GOPATH/bin); injects version
make build-all          # main binary, linux/darwin/windows cross-builds
make install            # install vigolium to $GOPATH/bin
make ensure-jstangle      # build & embed the bun-compiled jstangle binaries
make ensure-audit       # fetch/build the embedded vigolium-audit harness
make pack-jstangle      # zstd-pack staged jstangle blobs for go:embed (content-addressed)
make build-audit-external  # opt-in: bin/vigolium-audit-external downloads vigolium-audit lazily
```

## Test tiers

```bash
make test               # all tests (auto-installs gotestsum)
make test-unit          # fast unit tests only (-short, no external deps)
make test-race          # all tests with the race detector
make test-e2e           # Docker-based e2e (-tags=e2e), in test/e2e/
make test-canary        # against DVWA / VAmPI / Juice Shop (Docker, -tags=canary)
make test-integration   # XSS benchmark tests (-tags=integration)
make test-browser-conformance  # browser crawler contracts against a real headless browser
make test-coverage      # produce coverage.out
make coverage-gate      # enforce the COVERAGE_MIN floor against coverage.out
```

Run a single test:

```bash
go test -v -run TestName ./pkg/path/to/package/...
```

Run a single tagged test:

```bash
go test -v -tags=e2e -run TestName ./test/e2e/...
```

`make test-browser-conformance` runs the `//go:build integration` tests of
`pkg/spitolas/internal/{browser,form,crawler,condition}` — launcher and
security flags, dialog and submit-guard policy, form fill outcomes and
scoping, POST-submission attribution, crawler gates, wait conditions — against
a real headless Chrome/Chromium and local `httptest` fixtures (no Docker, no
internet). The `-short` unit run never executes these files, so this target is
where those contracts are checked. It first runs `TestConformancePrecheck` and
exits non-zero with an install hint when no browser can be launched, rather
than reporting a browserless run as green. Packages run one at a time (`-p 1`)
because several cases are timing-sensitive. `make test-race` names the
race-sensitive packages in its comment. CI does not run this target yet.

Vulnerable apps for e2e/canary are managed with Docker Compose under
`test/testdata/vulnerable-apps/`:

```bash
make apps-up            # start the vulnerable app stack
make apps-down          # tear it down
```

## Lint, format, tidy

```bash
make fmt                # gofmt the tree
make lint               # golangci-lint run (the CI gate)
make tidy               # go mod tidy
make verify-generated   # check gofmt + go.mod are clean (mirrors CI)
```

Linter config lives in `.golangci.yml` (golangci-lint v2). The enabled set is
deliberately conservative and kept green so `make lint` can gate CI:
`errcheck, govet, ineffassign, staticcheck, unused, misspell, errorlint`.
`gosec` and `bodyclose` are documented as deferred — see the comments in
`.golangci.yml` before enabling them.

## CI

`.github/workflows/ci.yml` runs only when started by hand (Actions tab or
`gh workflow run ci.yml`; `-f macos=true` adds the macOS job). It runs lint, `go vet`, race-disabled unit tests with a
coverage floor (`coverage-gate`, `COVERAGE_MIN`), plus informational
`govulncheck`, SBOM (CycloneDX), and dependency-review jobs. The vendored
`pkg/spitolas/rod` package and everything under `platform/` are excluded from
vet/test (see `GOLIST_EXCLUDE` in the Makefile and the `grep -Ev` filter in CI).

## Common gotchas

- **"package jstangle: no embedded binary"** → run `make ensure-jstangle`.
- **`pattern jstangle/jstangle-<os>-<arch>.zst: no matching files found`** → the
  raw helper exists but was never packed (a checkout from before compression,
  or a cache that restored only the raw blob). Run `make pack-jstangle` or
  `make build`.
- **Stale `./vigolium` in the repo root** → it's gitignored; delete it and use
  `make build` (→ `bin/vigolium`).
- **`platform/` is external tooling** — don't build or modify it (except the
  Next.js UI in `platform/vigolium-workbench/`).

See also: [project-structure.md](project-structure.md) and
[developing-modules.md](developing-modules.md).
