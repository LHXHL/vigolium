# Projects: Multi-Tenant Data Isolation

Projects isolate scan data in a shared Vigolium database. Scans, HTTP records,
findings, scopes, OAST interactions, scan logs, authentication mappings, and
agentic scans carry a `project_uuid`.

The built-in default project UUID is
`00000000-0000-0000-defa-c01001000001`.

## Project Commands

Create and list projects:

```bash
vigolium project create my-engagement \
  --description "Q3 application assessment"
vigolium project list
vigolium project ls -j      # read envelope: items = projects {uuid, name, active, …}
```

`project create` generates a UUID unless the global `--project-uuid` flag is
set explicitly. With `-j` it prints a mutation document whose `items[0].uuid`
is the new project's UUID.

Select a project:

```bash
eval "$(vigolium project use a1b2c3d4-e5f6-7890-abcd-ef1234567890)"
```

`project use` does two things:

- persists the selection in `~/.vigolium/active-project` for future commands
  (written atomically);
- when stdout is not a terminal (the `eval "$(...)"` case), prints an
  `export VIGOLIUM_PROJECT_UUID=...` line for the current shell. On a terminal
  it prints only the status on stderr. With `-j` it prints the mutation
  document instead, never the `export` line.

An unknown UUID is an error (exit 1, `error.code: "not_found"`) and nothing is
created or activated. Pass `--create` to create the project with that UUID;
`--name` and `--description` customize it:

```bash
vigolium project use a1b2c3d4-e5f6-7890-abcd-ef1234567890 --create --name acme -j
# {"kind":"mutation","changed":true,"action":"create","items":[{"uuid":"a1b2…","name":"acme",…}],
#  "env":{"VIGOLIUM_PROJECT_UUID":"a1b2…"},"activated_scope":"global",…}
```

`changed` is true when the project was created or the active-project file now
names a different project; re-activating the active project is
`"action":"noop"`. `VIGOLIUM_PROJECT_READONLY=true` refuses every activation,
not only one that creates a project.

Show the project configuration path:

```bash
vigolium project config
vigolium project config a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

Delete a project and its project-scoped data:

```bash
vigolium project delete a1b2c3d4-e5f6-7890-abcd-ef1234567890
vigolium project rm a1b2c3d4-e5f6-7890-abcd-ef1234567890 --force
vigolium project delete a1b2c3d4-e5f6-7890-abcd-ef1234567890 \
  --keep-config --force
```

The CLI refuses to delete the default project. Deleting a project that does
not exist is not an error: `project delete -j` reports `"changed": false,
"found": false`. The confirmation preview goes to stderr. Set
`VIGOLIUM_PROJECT_READONLY=true` to disable mutating project commands
(`create`, `use`, `delete`) in a shared or production environment.

## Selecting a Project

The CLI resolves the active project in this order:

1. `--project-uuid`
2. `--project-name`
3. `VIGOLIUM_PROJECT_UUID`
4. `VIGOLIUM_PROJECT_NAME`
5. `~/.vigolium/active-project`
6. the built-in default project

`--project-uuid` and `--project-name` are mutually exclusive. Likewise,
`VIGOLIUM_PROJECT_UUID` takes precedence over `VIGOLIUM_PROJECT_NAME` when both
are set.

`~/.vigolium/active-project` is global to the user: a `project use` in one
shell (or by one agent) re-scopes every other shell that has not pinned a
project. Every `-j` document therefore carries `project_source`: `flag`, `env`,
`active_file` or `default`. When a command's project actually came from the
active-project file, the document also carries a `warnings` entry telling you
to pin `--project-uuid` or `VIGOLIUM_PROJECT_UUID`. Automation and parallel
agents should always pin.

```bash
# Scan by project name
vigolium scan https://example.com --project-name my-engagement

# Query and export by project UUID
vigolium finding --project-uuid a1b2c3d4-e5f6-7890-abcd-ef1234567890
vigolium export --project-uuid a1b2c3d4-e5f6-7890-abcd-ef1234567890 \
  --format jsonl -o project.jsonl
```

For server requests, use `X-Project-UUID`:

```bash
curl http://localhost:9002/api/findings \
  -H 'Authorization: Bearer my-secret-key' \
  -H 'X-Project-UUID: a1b2c3d4-e5f6-7890-abcd-ef1234567890'
```

If the header is omitted, the server uses the default project. Project
selection is data scoping; it is not an email-domain authorization mechanism.

## Per-Project Configuration

The project overlay lives at:

```text
~/.vigolium/projects/<uuid>/config.yaml
```

It uses the same partial YAML shape as a scanning profile. Only the keys it
sets override the global settings; every other key keeps its global value.
`vigolium scope set --project <uuid> <key> <value>` writes one key into it.

```yaml
scope:
  host:
    include:
      - "*.example.com"

scanning_pace:
  concurrency: 30
  rate_limit: 50
```

Configuration precedence is:

```text
built-in defaults
  -> ~/.vigolium/vigolium-configs.yaml
  -> ~/.vigolium/projects/<uuid>/config.yaml
  -> --scanning-profile
  -> CLI flags
```

The project layer applies wherever a scan or a scope check runs under a
project:

- **CLI**: `scan`, `run`, `scan-url`/`scan-request` (runner path), `ingest`,
  `agent swarm`, `doctor` and `config validate --project` use the resolved
  project (`--project-uuid`/`--project-name`, their env vars, then
  `project use`, then the default project).
- **REST**: `POST /api/scans/run`, `POST /api/scan-all-records` and
  `POST /api/agent/run/swarm` use the `X-Project-UUID` project. The overlay is
  re-read when its file changes, so a `scope set --project` takes effect on
  the next REST scan without restarting the server. Request fields still
  outrank it.
- **Agent tools**: an olium `run_native_scan`/`run_module`/`run_extension` launch uses
  the project the agent runs in.

A standalone database runs global-only unless you name a project: under
`-S`/`--stateless`, `--glob-db`, or a shell pinned with `VIGOLIUM_DB_PATH`,
the `project use` selection contributes no overlay, while an explicit
`--project-uuid`/`--project-name` (or `VIGOLIUM_PROJECT_UUID`/`_NAME`) still
applies it. An overlay that exists but does not parse fails the scan rather
than running it with the wider global scope.

## Project REST API

The current endpoints are:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/projects` | List projects with aggregate statistics |
| `POST` | `/api/projects` | Create a project |
| `GET` | `/api/projects/:uuid` | Get one project with statistics |
| `GET` | `/api/projects/:uuid/stats` | Get statistics only |
| `PUT` | `/api/projects/:uuid` | Update name, description, or owner |
| `DELETE` | `/api/projects/:uuid` | Delete a project after reassigning its data to the default project |

Create a project with either a server-generated UUID or a client-supplied UUID:

```bash
curl -X POST http://localhost:9002/api/projects \
  -H 'Authorization: Bearer my-secret-key' \
  -H 'Content-Type: application/json' \
  -d '{
    "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "name": "my-engagement",
    "description": "Q3 application assessment"
  }'
```

The accepted project fields are `uuid` (create only), `name`, `description`,
and `owner_uuid`. See the [Projects API reference](api-references/projects.md)
for response schemas and error behavior.
