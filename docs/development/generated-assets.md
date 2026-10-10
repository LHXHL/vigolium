# Generated & machine-managed assets

This repo checks in a mix of hand-written code and machine-generated artifacts.
This page lists what is generated, how to regenerate it, and how it is verified.

## Diff-verifiable (checked by `make verify-generated`)

These are deterministic and must stay in sync with their source:

| Artifact | Source of truth | Regenerate with |
|---|---|---|
| `gofmt` formatting of all Go files | the Go source itself | `make fmt` |
| `go.mod` / `go.sum` | `import` statements | `make tidy` |
| REST API spec: `docs/development/api-swagger.json` and its embedded copy `pkg/server/swagger_spec.json` | `components.schemas`: the Go types registered in `pkg/server/swagger_types.go`; paths and prose: hand-written in the canonical JSON | `make swagger` |

`make verify-generated` fails if any of these is out of sync, so it is safe to run in
CI as a gate. It restores `go.mod`/`go.sum` after the tidy check so it never
leaves a dirty tree.

The Swagger generator (`internal/tools/swaggergen`) rebuilds each registered
schema from its struct and carries over hand-written descriptions, examples,
enums and `required` lists for properties that still exist; add prose for a
new field by editing the canonical JSON and re-running `make swagger`. The
`pkg/server` swagger tests additionally fail when a registered route has no
spec operation (or vice versa), when a schema's properties drift from its
struct, or when the spec stops validating as OpenAPI 3.

## Checked by `go test ./pkg/cli`

| Artifact | Test | Fix with |
|---|---|---|
| Skill flag reference `public/skills/vigolium-scanner/references/flags.generated.md` | `TestFlagsGeneratedIsCurrent` (also `make skill-flags-check`) | `make skill-flags` |
| Every documented `vigolium …` command: fenced `bash`/`sh`/`shell`/`zsh`/`console` blocks in the skill bundle, `README.md` and `docs/**`, the `--full-example` tour, and every cobra `Example`/`Long` | `TestDocCommands*` in `pkg/cli/doc_commands_test.go` | fix the command |

The doc-command test parses each command against the real command tree without
running it: unknown commands, subcommands and flags, deprecated flags,
positional arity and UUID/id positionals, enum values (`--only`/`--skip`
phases, `-I`, `--format`, severities, `--strategy`, `--intensity`), specs passed
to `-T`, shim translations, and `ext eval`/`js --code` snippets. Untagged and
`text` fences are not checked. For a synopsis line or a deliberate mistake, opt
out with ```` ```bash doccheck=skip ````, a `<!-- doccheck: skip -->` line before
the fence, or a trailing `# doccheck: skip`; a line that documents a deprecated
flag on purpose takes `# doccheck: deprecated-ok`. Inline `` `vigolium …` ``
spans in the skill files are reported in the test log only, for now.

## Build outputs (not diff-verifiable)

These are non-deterministic binary/bundle outputs. They are regenerated from
external toolchains (Bun, GoReleaser, the UI build) and are **not** verified by
`make verify-generated` because byte-for-byte reproduction is not guaranteed:

| Artifact | Path | Regenerate with |
|---|---|---|
| jstangle binaries (embedded per-platform as `.zst` + `.pin`) | `internal/resources/deparos/jstangle/` | `make ensure-jstangle` / `make update-jstangle` / `make pack-jstangle` |
| vigolium-audit harness binary (embedded as `vigolium-audit.zst` + `.pin`) | `pkg/audit/bin/_bin/` | `make update-audit` / `make ensure-audit` |
| `audit_external` pins table and download assets | `pkg/audit/bin/pins_gen.go`, `build/dist-helpers/` | `make audit-external-pins` |
| Workbench UI bundle & report template | `public/ui/`, `public/static-reports/template.html` | `make update-ui` |
| Release metadata | `build/dist/metadata.json` | `make generate-metadata` |

`make deps` builds the jstangle binaries needed to compile the tree (they are
embedded via `//go:embed`), which is why CI runs it before any `go build`.

## Linting

Generated files are excluded from `golangci-lint` via the `exclusions.generated:
lax` setting in `.golangci.yml`, plus an explicit skip for the vendored
`pkg/spitolas/rod/` browser-automation package (which is also excluded from
`go vet`/tests in the Makefile and CI).
