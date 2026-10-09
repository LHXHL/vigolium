# Server Mode: Ingesting Data via the API

This guide covers how to start Vigolium in server mode and ingest HTTP traffic into the database using the REST API and CLI.

## Starting the Server

```bash
# Start with an API key
export VIGOLIUM_API_KEY=my-secret-key
vigolium server

# Expose the API beyond this machine, on a custom port
export VIGOLIUM_API_KEY=my-secret-key
vigolium server --host 0.0.0.0 --service-port 9002

# With transparent HTTP proxy for recording traffic
export VIGOLIUM_API_KEY=my-secret-key
vigolium server --ingest-proxy-port 9003

# Without authentication (development only)
vigolium server -A
```

The server listens on `127.0.0.1:9002` by default. Pass `--host 0.0.0.0` (or set
`VIGOLIUM_SERVER_HOST=0.0.0.0`, as the Docker images do) to accept remote
connections; the ingest proxy keeps its own `--ingest-proxy-host` (also
loopback by default).

## CORS Configuration

The server's CORS behavior is controlled by `cors_allowed_origins` in `~/.vigolium/vigolium-configs.yaml`:

```yaml
server:
  cors_allowed_origins: reflect-origin
```

| Value | Behavior |
|-------|----------|
| `reflect-origin` (default) | Echoes the requesting `Origin` header back. Allows credentials. |
| `*` | Allows all origins without credentials (standard wildcard). |
| _(empty string)_ | Disables CORS middleware entirely. |
| `https://app.example.com, https://admin.example.com` | Comma-separated allowlist. Allows credentials. |

## Project Scoping

All server operations are scoped to a project via the `X-Project-UUID` request header. If omitted, the default project is used.

```bash
# Ingest into a specific project
curl -X POST http://localhost:9002/api/ingest-http \
  -H "Authorization: Bearer my-secret-key" \
  -H "X-Project-UUID: a1b2c3d4-..." \
  -H "Content-Type: application/json" \
  -d '{"input_mode": "url", "content": "https://example.com"}'
```

All queries (findings, HTTP records, stats, scans) return data scoped to the project specified in the header. See [Projects](projects.md) for the full multi-tenancy reference.

## Authentication

Protected API routes require a Bearer token. Health/metrics, login, Swagger,
and static UI routes are public:

```
Authorization: Bearer my-secret-key
```

API key resolution order: `VIGOLIUM_API_KEY` env var > `server.auth_api_key` in config file.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Dashboard UI (no auth required) |
| GET | `/health` | Health check (no auth required) |
| GET | `/ready` | Readiness check (no auth required) |
| GET | `/metrics` | Prometheus metrics (no auth required) |
| GET | `/swagger/*` | Swagger UI and OpenAPI spec (no auth required) |
| GET | `/server-info` | Server status, queue depth, record/finding counts |
| GET | `/api/modules` | List available scanner modules |
| GET | `/api/http-records` | Query stored HTTP records |
| GET | `/api/findings` | Query scan findings |
| POST | `/api/ingest-http` | Ingest HTTP traffic into the database |
| GET | `/api/stats` | Aggregated scan statistics |
| GET | `/api/scope` | View scope configuration |
| POST | `/api/scope` | Update scope configuration |
| GET | `/api/config` | View server configuration |
| POST | `/api/config` | Update server configuration |
| POST | `/api/scans/run` | Trigger a target-based background scan |
| GET | `/api/scan/status` | Check scan status |
| POST | `/api/scans/:uuid/stop` | Stop a running scan |
| POST | `/api/agent/run/query` | Single-shot agent prompt execution |
| POST | `/api/agent/run/autopilot` | Autonomous AI-driven scanning session |
| POST | `/api/agent/run/swarm` | AI-guided targeted vulnerability swarm |
| POST | `/api/agent/run/audit` | Unified audit dispatcher (`auto`, `both`, `audit`, or `piolium`) |
| GET | `/api/agent/status/list` | List agent runs |
| GET | `/api/agent/status/:id` | Get agent run status (includes full result when completed) |

## Ingesting Data via API

The `/api/ingest-http` endpoint accepts multiple input modes. All requests use `POST` with a JSON body.

### Declaring the Pushing Tool

Records ingested through this endpoint are stored with `source: "ingest-server"`
by default — the same label every HTTP client shares. A client can name itself
instead, so its traffic is distinguishable later:

```bash
curl -X POST http://localhost:9002/api/ingest-http \
  -H "X-Vigolium-Source: caido" \
  ...
```

Accepted values are `burp` and `caido` — the same labels the bridge path writes,
so one `--source caido` filter covers traffic that arrived either by Vigolium
pulling over the bridge or by the plugin pushing here. The Vigolium Caido plugin
sets this automatically.

The list is a closed allowlist rather than a passthrough, and anything else
falls back to `ingest-server`. `source` is not only a display label: it decides
which rows scan-on-receive feeds back into a running scan, so a client free to
claim `scanner` could silently exclude its own traffic from the scan it just
asked for.

### Ingest a Single URL

```bash
curl -X POST http://localhost:9002/api/ingest-http \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "input_mode": "url",
    "content": "https://example.com/api/users?id=1"
  }'
```

### Ingest Multiple URLs (url_file mode)

Pass a newline-separated list of URLs. Lines starting with `#` are treated as comments.

```bash
curl -X POST http://localhost:9002/api/ingest-http \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "input_mode": "url_file",
    "content": "https://example.com/api/users?id=1\nhttps://example.com/api/posts?page=2\nhttps://example.com/login"
  }'
```

### Ingest a curl Command

```bash
curl -X POST http://localhost:9002/api/ingest-http \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "input_mode": "curl",
    "content": "curl -X POST https://example.com/api/login -H \"Content-Type: application/json\" -d \"{\\\"username\\\":\\\"admin\\\",\\\"password\\\":\\\"test\\\"}\""
  }'
```

Using `content_base64` to avoid JSON escaping issues:

```bash
# Encode the curl command
ENCODED=$(echo -n 'curl -X POST https://example.com/api/login -H "Content-Type: application/json" -d "{\"username\":\"admin\",\"password\":\"test\"}"' | base64)

curl -X POST http://localhost:9002/api/ingest-http \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d "{
    \"input_mode\": \"curl\",
    \"content_base64\": \"$ENCODED\"
  }"
```

### Ingest a Raw HTTP Request (Burp-style)

Send a base64-encoded raw HTTP request, optionally with its response:

```bash
# Encode raw request
RAW_REQ=$(printf 'GET /api/users?id=1 HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc123\r\n\r\n' | base64)

curl -X POST http://localhost:9002/api/ingest-http \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d "{
    \"input_mode\": \"burp_base64\",
    \"http_request_base64\": \"$RAW_REQ\"
  }"
```

With both request and response:

```bash
RAW_REQ=$(printf 'POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{"username":"admin","password":"test"}' | base64)
RAW_RESP=$(printf 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"token":"eyJhbGciOiJIUzI1NiJ9..."}' | base64)

curl -X POST http://localhost:9002/api/ingest-http \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d "{
    \"input_mode\": \"burp_base64\",
    \"http_request_base64\": \"$RAW_REQ\",
    \"http_response_base64\": \"$RAW_RESP\"
  }"
```

### Ingest a Raw HTTP Request with a URL Hint

Raw HTTP requests don't contain the scheme (`https` vs `http`), and the `Host` header may not match the public hostname (e.g. behind a load balancer). Use the `url` field to provide the correct scheme and host:

```bash
RAW_REQ=$(printf 'POST /api/login HTTP/1.1\r\nHost: internal-lb\r\nContent-Type: application/json\r\n\r\n{"user":"admin"}' | base64)

curl -X POST http://localhost:9002/api/ingest-http \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d "{
    \"input_mode\": \"burp_base64\",
    \"url\": \"https://app.example.com\",
    \"http_request_base64\": \"$RAW_REQ\"
  }"
```

### Ingest an OpenAPI / Swagger Spec

```bash
curl -X POST http://localhost:9002/api/ingest-http \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "input_mode": "openapi",
    "content": "{\"openapi\":\"3.0.0\",\"info\":{\"title\":\"Example\",\"version\":\"1.0\"},\"servers\":[{\"url\":\"https://api.example.com\"}],\"paths\":{\"/users\":{\"get\":{\"summary\":\"List users\"}},\"/users/{id}\":{\"get\":{\"summary\":\"Get user\",\"parameters\":[{\"name\":\"id\",\"in\":\"path\",\"required\":true,\"schema\":{\"type\":\"integer\"}}]}}}}"
  }'
```

Using base64 for larger specs:

```bash
SPEC=$(base64 < openapi.yaml)

curl -X POST http://localhost:9002/api/ingest-http \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d "{
    \"input_mode\": \"openapi\",
    \"content_base64\": \"$SPEC\"
  }"
```

### Ingest a Postman Collection

```bash
COLLECTION=$(base64 < collection.json)

curl -X POST http://localhost:9002/api/ingest-http \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d "{
    \"input_mode\": \"postman_collection\",
    \"content_base64\": \"$COLLECTION\"
  }"
```

## Ingesting Data via CLI

The `vigolium ingest` command supports both remote (server) and local (direct-to-database) modes.

### Remote Ingestion (to a running server)

```bash
export VIGOLIUM_API_KEY=my-secret-key

# Pipe URLs from stdin
cat urls.txt | vigolium ingest -s http://localhost:9002

# From a file
vigolium ingest -s http://localhost:9002 --input targets.txt

# OpenAPI spec with a base URL
vigolium ingest -s http://localhost:9002 \
  --input api.yaml -I openapi -t https://api.example.com

# Control submission rate
vigolium ingest -s http://localhost:9002 \
  --input urls.txt --concurrency 20 -r 200
```

### Local Ingestion (direct to database)

When `--server` is omitted, requests are fetched and stored directly in the local database:

```bash
# Ingest URLs (fetches each and stores request + response)
cat urls.txt | vigolium ingest

# From an OpenAPI spec
vigolium ingest --input api.yaml -I openapi -t https://api.example.com

# With a custom scan ID for tagging
vigolium ingest --input urls.txt --scan-uuid recon-2026-02

# Use a specific database file
vigolium ingest --input urls.txt --db ./project.db

# Ingest into a specific project
vigolium ingest --input urls.txt --project-uuid a1b2c3d4-...
```

## Ingesting via Transparent Proxy

Start the server with a proxy port to passively record HTTP traffic:

```bash
export VIGOLIUM_API_KEY=my-secret-key
vigolium server --ingest-proxy-port 9003
```

Then route your tools through the proxy:

```bash
# curl through the proxy
curl -x http://localhost:9003 https://example.com/api/users

# httpx through the proxy
echo "https://example.com" | httpx -proxy http://localhost:9003

# nuclei through the proxy
nuclei -u https://example.com -proxy http://localhost:9003
```

The proxy binds `127.0.0.1` (`--ingest-proxy-host`). To accept clients from
other machines, bind a routable address and gate it with `--proxy-token` and/or
`--proxy-allow <cidr>`; the server refuses to start an ungated proxy on a
non-loopback address. See [Transparent Proxy](server-mode/proxy.md#access-control).

Plain HTTP traffic is recorded. HTTPS `CONNECT` is an opaque tunnel by
default. To capture authorized HTTPS traffic, trust the generated CA, then
enable MITM:

```bash
vigolium server ca install          # prints the trust commands; --yes runs them
vigolium server --ingest-proxy-port 9003 --proxy-mitm
```

Use `--proxy-insecure` only when the upstream test service has an intentionally
untrusted certificate.

## Querying Ingested Data

To merge live proxy history into the same traffic API, enable the Bridge
listener in the Vigolium Burp extension or the Vigolium Caido plugin and start
the server with:

```bash
vigolium server --burp-bridge-url http://127.0.0.1:9009
```

`--caido-bridge-url` is an alias for the same flag — both plugins speak one
protocol, so which one is listening is discovered rather than declared.

The `/api/http-records` examples below then query the combined database and
live result set. No separate bridge search route is needed.

Live records are identified by their source: `"source": "burp"` or
`"source": "caido"`, taken from the `implementation` the listener reports on
every reply. A listener too old to report one is read as Burp. The response
also carries `X-Vigolium-Bridge-Source` naming the vendor that answered, so a
client can label the merged page without inspecting each row.

Filtering by `?source=` works as expected in both directions: `?source=caido`
against a Burp listener returns only the database's own Caido rows, and vice
versa.

### List HTTP Records

```bash
# All records (paginated, default limit=50)
curl -s http://localhost:9002/api/http-records \
  -H "Authorization: Bearer my-secret-key" | jq .

# Filter by domain
curl -s "http://localhost:9002/api/http-records?domain=example.com" \
  -H "Authorization: Bearer my-secret-key" | jq .

# Filter by status code and method
curl -s "http://localhost:9002/api/http-records?status_code=200,302&method=GET,POST" \
  -H "Authorization: Bearer my-secret-key" | jq .

# Search across URLs and headers
curl -s "http://localhost:9002/api/http-records?search=admin&limit=10" \
  -H "Authorization: Bearer my-secret-key" | jq .

# Pagination
curl -s "http://localhost:9002/api/http-records?limit=20&offset=40" \
  -H "Authorization: Bearer my-secret-key" | jq .
```

### List Findings

```bash
# All findings
curl -s http://localhost:9002/api/findings \
  -H "Authorization: Bearer my-secret-key" | jq .

# Filter by severity
curl -s "http://localhost:9002/api/findings?severity=high,critical" \
  -H "Authorization: Bearer my-secret-key" | jq .

# Filter by module
curl -s "http://localhost:9002/api/findings?module_name=xss-light-url-params" \
  -H "Authorization: Bearer my-secret-key" | jq .

# Filter by domain
curl -s "http://localhost:9002/api/findings?domain=example.com" \
  -H "Authorization: Bearer my-secret-key" | jq .
```

### Server Info

```bash
curl -s http://localhost:9002/server-info \
  -H "Authorization: Bearer my-secret-key" | jq .
```

Response:

```json
{
  "version": "0.1.0",
  "uptime": "2h15m30s",
  "service_addr": "127.0.0.1:9002",
  "proxy_addr": "127.0.0.1:9003",
  "proxy_auth": "none",
  "queue_depth": 0,
  "total_records": 1542,
  "total_findings": 23
}
```

## Scan Management via API

After ingesting HTTP records, trigger a vulnerability scan via the API.

### Trigger a Scan

```bash
curl -s -X POST http://localhost:9002/api/scans/run \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"targets":["https://example.com"]}' | jq .
```

Force re-scan with specific modules:

```bash
curl -s -X POST http://localhost:9002/api/scans/run \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["https://example.com"],
    "modules": ["xss-scanner", "sqli-error-based"]
  }' | jq .
```

Returns `202 Accepted` on success. Target-less requests are rejected; use
`POST /api/scan-all-records` to scan the records already in the database.

### Check Scan Status

```bash
curl -s http://localhost:9002/api/scan/status \
  -H "Authorization: Bearer my-secret-key" | jq .
```

### Stop a Running Scan

```bash
curl -s -X POST http://localhost:9002/api/scans/<scan-uuid>/stop \
  -H "Authorization: Bearer my-secret-key" | jq .
```

See the [API Reference](api-references/scan.md) for full request/response details.

## Running AI Agents via API

The agent API provides query, autopilot, swarm, and unified audit run modes.
Runs use separate light/heavy concurrency pools; a saturated pool waits for the
configured queue timeout and then returns `429 Too Many Requests`.

### Query — Single-Shot Agent Run

```bash
curl -s -X POST http://localhost:9002/api/agent/run/query \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "agent": "claude",
    "prompt_template": "code-review",
    "source": "/home/user/src/my-app"
  }' | jq .
```

At least one of `prompt_template`, `prompt_file`, or `prompt` is required. Returns `202 Accepted` on success. Set `"stream": true` for real-time SSE output.

### Autopilot — Autonomous Scanning

```bash
curl -s -X POST http://localhost:9002/api/agent/run/autopilot \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "focus": "API injection",
    "stream": true
  }'
```

### Swarm — AI-Guided Scanning

```bash
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "input": "https://example.com",
    "discover": true,
    "profile": "thorough",
    "stream": true
  }'
```

SSE events are `data:` lines with JSON payloads: `{"type":"chunk","text":"..."}` for real-time output, `{"type":"phase","phase":"..."}` for swarm phase transitions, `{"type":"done","result":{...}}` on completion, or `{"type":"error","error":"..."}` on failure.

### List All Agent Runs

```bash
curl -s http://localhost:9002/api/agent/status/list \
  -H "Authorization: Bearer my-secret-key" | jq .
```

### Check Agent Run Status

```bash
curl -s http://localhost:9002/api/agent/status/agt-550e8400... \
  -H "Authorization: Bearer my-secret-key" | jq .
```

Once the run completes, the response includes a `result` field with the full agent output (raw text, findings, HTTP records).

See [Agent Mode](agentic-scan/agent-mode.md) for the full agent documentation (including autopilot, swarm, context enrichment, and prompt templates) and the [API Reference](api-references/agent.md) for request/response details.

## Input Modes Reference

| Mode | Content Field | Description |
|------|--------------|-------------|
| `url` | `content` | A single URL |
| `url_file` | `content` | Newline-separated list of URLs |
| `curl` | `content` or `content_base64` | A curl command string |
| `burp_base64` | `http_request_base64` | Base64-encoded raw HTTP request |
| `openapi` / `swagger` | `content` or `content_base64` | OpenAPI/Swagger spec (JSON or YAML) |
| `postman_collection` | `content` or `content_base64` | Postman Collection (JSON) |
| `auto` | `content` or `content_base64` | Detect the format from the content (`detected_format` in the response) |
| any `-I` format name | `content` or `content_base64` | `har`, `wsdl`, `burpxml`, `burpraw`, `burpscope`, `nuclei`, `deparos`, … — the same names and aliases the CLI's `-I` accepts |

See the [ingestion API reference](api-references/ingestion.md) for `variables`, `skipped_reasons` and the full mode table.

For `burp_base64` mode, you can also include `http_response_base64` to store the response alongside the request.

For modes that accept large payloads, prefer `content_base64` to avoid JSON escaping issues.
