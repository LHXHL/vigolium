# Vigolium API Reference — Overview

Base URL: `http://localhost:9002` (default)

## Starting the Server

```bash
# No authentication (development)
vigolium server -A

# With API key
export VIGOLIUM_API_KEY="my-secret-key"
vigolium server

# Custom port; the API binds 127.0.0.1 unless --host (or $VIGOLIUM_SERVER_HOST) says otherwise
vigolium server -A --service-port 8080
vigolium server --host 0.0.0.0        # reachable from other machines
```

## Authentication

Protected routes require a Bearer token when the server is started normally.
The key comes from `VIGOLIUM_API_KEY` or `server.auth_api_key`; file-backed
users can also log in at `POST /api/auth/login`. Pass `-A/--no-auth` only for a
trusted local development server.

```bash
curl -H "Authorization: Bearer my-secret-key" http://localhost:9002/api/stats
```

Public endpoints (no auth required): the dashboard/static assets at `/`,
`GET /health`, `GET /ready`, `GET /swagger/*`, `GET /metrics`, and
`POST /api/auth/login`. `/server-info` and other `/api/*` routes are protected.

## Project Scoping

Data API operations are scoped to a project via the `X-Project-UUID` request
header. If the header is omitted, the default project
(`00000000-0000-0000-defa-c01001000001`) is used.

```bash
# Scope requests to a specific project
curl -H "Authorization: Bearer my-secret-key" \
     -H "X-Project-UUID: a1b2c3d4-..." \
     http://localhost:9002/api/findings
```

This applies to data endpoints such as ingestion, findings, HTTP records,
stats, scans, storage, agent runs, and OAST interactions. See
[Projects](../projects.md) for the full multi-tenancy reference.

The header must name a project that exists:

| Header value | Response |
|---|---|
| absent, or the default project UUID | request runs in the default project |
| not a UUID | `400` `invalid_project_uuid` |
| a UUID with no project | `404` `project_not_found` |
| a UUID with no project, plus `X-Project-Create: 1` (or `?create=1`) | the project is created, then the request runs |
| any value, when the project lookup itself fails | `503` `database_unavailable` |

`server.auto_create_projects: true` restores the old behaviour of creating any
unknown UUID on first use. The header is ignored on the public endpoints,
`POST /api/auth/login`, and the project-management routes (`/api/projects`,
`/api/projects/:uuid/...`), so a client whose stored UUID went stale can still
list projects and pick another.

```bash
# Create the project on first use
curl -H "Authorization: Bearer my-secret-key" \
     -H "X-Project-UUID: 6f1c2a9e-0b7d-4c55-9a51-2f0e8c1d3b7a" \
     -H "X-Project-Create: 1" \
     http://localhost:9002/api/findings
```

## Response Versions

Every response carries a `Vigolium-Api-Version` header naming the body shape it
used. A client picks one with any of (first match wins):

1. `?api_version=2` (or `1`)
2. `Vigolium-Api-Version: 2` request header
3. `Accept: application/vnd.vigolium.v2+json` (or `...v1+json`)

Without one, the server uses `server.api_version_default` (1 in this release).
An unknown version is `400` `unsupported_api_version`. Server-sent event
streams are never wrapped.

**v1** is the historical shape, extended only additively. Paginated lists
(`/api/findings`, `/api/http-records`, `/api/scans`, `/api/oast-interactions`,
`/api/agent/sessions`) gain `schema_version: 1` and `command`; other list
endpoints keep their own shapes.

```json
{"schema_version": 1, "command": "finding", "project_uuid": "...",
 "data": [ ... ], "total": 150, "limit": 50, "offset": 0, "has_more": true}
```

**v2** is the CLI's `-j` envelope. Every list endpoint (including
`/api/modules`, `/api/extensions`, `/api/projects`, `/api/config` and
`/api/db/tables/...`) answers:

```json
{"schema_version": 2, "command": "finding", "kind": "read", "ok": true,
 "route": "GET /api/findings", "project_uuid": "...", "project_scoped": true,
 "total": 150, "offset": 0, "limit": 50, "has_more": true,
 "items": [ ... ], "generated_at": "2026-10-10T08:00:00.000Z", "generated_at_ms": 1791590400000}
```

`items` is always an array. `command` is the CLI command that reads the same
data (`finding`, `traffic`, `module ls`, …), or the route when there is none.
Endpoint-specific fields (for example `extensions_enabled`, or `table` and
`columns` on the table browser) sit next to these keys.

---

## GET / — Dashboard

Serves the dashboard HTML and its static assets. Application metadata is
available from the authenticated `GET /api/info` endpoint.

```bash
curl -s http://localhost:9002/ | head
```

## GET /api/info — App Info

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:9002/api/info | jq .
```

```json
{
  "name": "vigolium",
  "version": "v0.3.2",
  "author": "@j3ssie",
  "docs": "https://docs.vigolium.com",
  "build_time": "2026-07-14T08:08:41Z",
  "commit": "c50ba85"
}
```

---

## GET /api/diagnostics — System Readiness Check

Returns a diagnostic report checking database, agent backend, third-party tools, queue health, and directory configuration. See [Diagnostics](diagnostics.md) for full details.

```bash
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:9002/api/diagnostics | jq .status
```

```json
"ready"
```

---

## GET /health — Health Check

Returns server health status.

```bash
curl -s http://localhost:9002/health | jq .
```

```json
{
  "status": "healthy",
  "timestamp": "2026-02-16T15:30:00Z"
}
```

---

## GET /ready — Readiness Check

Returns `200` when the server is ready to accept work and `503` when its
database is unavailable. Unlike `/health`, this endpoint performs a database
ping.

```bash
curl -s http://localhost:9002/ready | jq .
```

---

## GET /server-info — Server Info

Returns detailed server information including uptime, database driver, queue depth, and record/finding totals.

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:9002/server-info | jq .
```

```json
{
  "name": "vigolium",
  "version": "v0.3.2",
  "author": "@j3ssie",
  "docs": "https://docs.vigolium.com",
  "build_time": "2026-07-14T08:08:41Z",
  "commit": "c50ba85",
  "uptime": "5m32s",
  "service_addr": "127.0.0.1:9002",
  "proxy_addr": "127.0.0.1:9003",
  "proxy_auth": "token",
  "queue_depth": 0,
  "total_records": 1234,
  "total_findings": 42,
  "license": "community-demo",
  "demo_only": true,
  "view_only": false,
  "mirror_dropped": 0
}
```

`license`, `demo_only`, and `view_only` are omitted when unset/false.
`proxy_addr` and `proxy_auth` (`none`, `token`, `allowlist` or
`token+allowlist`) appear only when the ingest proxy is on. `mirror_dropped`
appears only with `--mirror-fs`: it counts mirror jobs dropped because the
mirror writer stayed saturated for more than 2s (the database is unaffected). Configure `license` under `server.license` in `vigolium-configs.yaml`; `demo_only` / `view_only` reflect the `--demo-only` / `--view-only` server flags.

---

## GET /swagger/* — Swagger UI

Interactive API documentation. Open in a browser.

```
http://localhost:9002/swagger/
```

The raw OpenAPI 3.0 spec is available at:

```bash
curl -s http://localhost:9002/swagger/doc.json | jq .info
```

---

## GET /metrics — Prometheus Metrics

Returns Prometheus-formatted metrics without authentication when
`server.enable_metrics` is enabled (the default).

```bash
curl -s http://localhost:9002/metrics
```

---

## CORS

CORS can be enabled via the `cors_allowed_origins` server config:

| Value              | Behavior                                              |
|--------------------|-------------------------------------------------------|
| `*`                | Allow all origins                                     |
| `reflect-origin`   | Reflect the request's `Origin` header (allows credentials) |
| `origin1,origin2`  | Allow specific origins (comma-separated, allows credentials) |
| *(empty/omitted)*  | CORS disabled                                         |

Allowed methods: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`. Allowed
headers: `Content-Type`, `Authorization`, `X-Project-UUID`, `X-User-Email`,
`X-Vigolium-Source`, `Vigolium-Api-Version` and `X-Project-Create`. The
`Vigolium-Api-Version` response header is exposed to scripts.

---

## Error Responses

Every non-2xx response (including unknown routes and wrong methods) has a JSON
body with a stable string code. Branch on the string code, never on the
message.

v1 (default):

```json
{
  "error": "scan not found",
  "code": 404,
  "error_code": "scan_not_found",
  "details": "optional additional details"
}
```

`code` is always the HTTP status. v2:

```json
{
  "schema_version": 2,
  "command": "GET /api/scans/:uuid",
  "route": "GET /api/scans/:uuid",
  "ok": false,
  "error": {"code": "scan_not_found", "message": "scan not found", "status": 404},
  "generated_at": "2026-10-10T08:00:00.000Z",
  "generated_at_ms": 1791590400000
}
```

The codes are the same closed set the CLI reports in `error.code` (the Swagger
spec lists them as an enum). Codes the API returns include `invalid_request`,
`unauthorized`, `forbidden`, `not_found`, `scan_not_found`, `record_not_found`,
`finding_not_found`, `project_not_found`, `invalid_project_uuid`,
`method_not_allowed`, `conflict`, `payload_too_large`, `rate_limited`,
`queue_full`, `unsupported_input_mode`, `input_unparsed`,
`no_targets_in_scope`, `database_locked`, `database_unavailable`,
`service_unavailable`, `unsupported_api_version` and `internal_error`. A route
that has no specific code uses the one for its status class.

**HTTP statuses:**

| Code | Meaning                                      |
|------|----------------------------------------------|
| 400  | Bad request (invalid JSON, missing fields)   |
| 401  | Unauthorized (missing or invalid Bearer token) |
| 403  | Authenticated but role/mode does not allow the operation |
| 404  | Not found (e.g. agent run ID not found)      |
| 409  | Conflict (for example, a project scan is already running) |
| 429  | Agent concurrency pool or per-project quota is saturated |
| 500  | Internal server error                         |
| 503  | Database not available                        |
