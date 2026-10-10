# Transparent Proxy

## Overview

Vigolium's server mode includes a built-in transparent HTTP proxy that passively records all traffic flowing through it. This lets you point any HTTP-capable tool at Vigolium and have its traffic automatically ingested for scanning.

## Starting the Proxy

Start the server with `--ingest-proxy-port` to enable the transparent proxy alongside the REST API:

```bash
export VIGOLIUM_API_KEY=my-secret-key
vigolium server --ingest-proxy-port 9003
```

This starts two listeners, both on `127.0.0.1` by default:
- **REST API** on port `9002` (default; `--host`)
- **HTTP proxy** on port `9003` (`--ingest-proxy-host`)

## Access Control

The proxy is an open forward proxy that writes into your database, so it binds
loopback unless told otherwise, independently of the API's `--host`. Binding it
to a routable address requires a gate; without one the server exits 2 before it
listens:

```bash
# Token (or config server.ingest_proxy_token)
vigolium server --ingest-proxy-port 9003 --ingest-proxy-host 0.0.0.0 --proxy-token "$PROXY_TOKEN"

# Client allow-list, repeatable (or config server.ingest_proxy_allow)
vigolium server --ingest-proxy-port 9003 --ingest-proxy-host 0.0.0.0 --proxy-allow 10.0.0.0/8
```

Clients send the token as `Proxy-Authorization`: `Basic` with any username and
the token as password (what `http://user:token@host:port` proxy URLs produce), or
`Bearer <token>`. A missing or wrong token gets `407 Proxy Authentication
Required` with `Proxy-Authenticate: Basic realm="vigolium"`; a client outside the
allow-list gets `403`; with both set, both must pass. The header is stripped
before the request is forwarded or recorded, so the token never reaches the
target or the database.

## How It Works

The proxy sits between your tools and the target. All HTTP traffic passing through is automatically recorded in the database as HTTP records, ready for scanning.

HTTPS `CONNECT` tunnels pass through without recording by default. Enable
explicit MITM mode when you control the client and target environment:

```bash
# Trust the generated CA on this machine (prints the commands; --yes runs them),
# or write it out for a client: vigolium server ca print --out ./vigolium-proxy-ca.pem
vigolium server ca install
vigolium server --ingest-proxy-port 9003 --proxy-mitm
```

`vigolium server ca` manages the CA (`~/.vigolium/ca`, created on first use):

| Command | Does |
|---|---|
| `server ca path` | Print the certificate path |
| `server ca print [--out FILE]` | PEM to stdout or a file; `-j` gives `path`, `sha256`, `subject`, `not_after` |
| `server ca install [--yes]` | macOS login keychain, Debian/Ubuntu `update-ca-certificates`, Fedora/RHEL `update-ca-trust`, Windows `certutil -user`; prints the commands unless `--yes` |
| `server ca uninstall [--yes]` | Remove that trust again |

Firefox (and Chrome on Linux) keep their own NSS store; `install` prints the
command for it as a note. `--export-ca FILE` remains as a hidden alias of
`server ca print --out FILE`.

`--proxy-insecure` skips verification of the upstream server certificate and
should be reserved for authorized test systems with self-signed TLS.

## Usage Examples

### curl (HTTPS capture with `--proxy-mitm`)

```bash
curl -x http://localhost:9003 \
  --cacert ./vigolium-proxy-ca.pem https://example.com/api/users
```

### httpx

```bash
echo "https://example.com" | httpx -proxy http://localhost:9003
```

### nuclei

```bash
nuclei -u https://example.com -proxy http://localhost:9003
```

### Browser

Configure your browser's HTTP proxy to `localhost:9003`. In most browsers this is under network or proxy settings. For Firefox, go to Settings > Network Settings > Manual proxy configuration and set the HTTP Proxy to `localhost` with port `9003`.

For any HTTPS client, trust the exported CA and start the proxy with
`--proxy-mitm`; otherwise the connection succeeds as an opaque tunnel and is
not recorded.

## Querying Ingested Data

After routing traffic through the proxy, use the REST API to inspect what was recorded and view any scan findings.

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
