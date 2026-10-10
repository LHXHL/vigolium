# Vigolium API Reference — Ingestion

## POST /api/ingest-http — Ingest HTTP Data

Import HTTP request/response data into the database for scanning. Supports multiple input formats.

**Headers:**

| Header            | Required | Description                                                        |
|-------------------|----------|--------------------------------------------------------------------|
| `Content-Type`    | Yes      | Must be `application/json`                                         |
| `X-Project-UUID`  | No       | Project UUID to scope the imported data. Falls back to the default project if omitted. |

**Request body:**

| Field                  | Type   | Required | Description                              |
|------------------------|--------|----------|------------------------------------------|
| `input_mode`           | string | Yes      | Input format (see modes below)           |
| `url`                  | string | No       | Base URL for `openapi`, endpoint for `wsdl`, `{{baseUrl}}` for `postman`; overrides the host of each record for the other modes |
| `content`              | string | No       | Raw content (plaintext)                  |
| `content_base64`       | string | No       | Base64-encoded content                   |
| `http_request_base64`  | string | No       | Base64-encoded raw HTTP request (for `burp_base64`) |
| `http_response_base64` | string | No       | Base64-encoded raw HTTP response (for `burp_base64`) |
| `variables`            | object | No       | Values for Postman `{{name}}` placeholders and OpenAPI/WSDL parameters and credentials (the REST form of `--spec-var`), e.g. `{"baseUrl": "https://api.example.com", "bearer": "<token>"}` |

**Input modes:**

`input_mode` takes the same format names and aliases as the CLI's `-I`, plus three REST-only single-item modes and `auto`. An unknown mode returns 400 (`unsupported_input_mode`) with every accepted value in `details`.

| Mode                  | Description                          | Content field  |
|-----------------------|--------------------------------------|----------------|
| `auto`                | Detect the format from the content (same detector as `-i` without `-I`); the response's `detected_format` names it. Undetectable content returns 400 (`input_unparsed`) | `content`      |
| `url`                 | Single URL                           | `content`      |
| `curl`                | Single curl command                  | `content`      |
| `burp_base64`         | Base64 raw HTTP request (+response)  | `http_request_base64` |
| `urls` / `url_file` / `url` list aliases | Newline-separated list of URLs; `#` comments skipped. Content that is mostly not URLs returns 400 (`input_unparsed`) naming the format it resembles | `content`      |
| `openapi` / `swagger` | OpenAPI/Swagger spec (JSON or YAML)  | `content`      |
| `postman` / `postman_collection` | Postman Collection v2      | `content`      |
| `har` / `http_archive`| HAR (HTTP Archive) 1.2 JSON          | `content`      |
| `wsdl` / `soap`       | WSDL 1.1 service description (`url` = endpoint) | `content` |
| `burpxml` / `burp`    | Burp "Save items" XML export         | `content`      |
| `burpraw` / `raw`     | Raw HTTP request, optionally `***` + response | `content` |
| `burpscope`           | Burp scope / project config (include rules → URLs) | `content` |
| `nuclei`              | Nuclei JSONL output                  | `content`      |
| `deparos`             | Deparos discovery JSONL              | `content`      |

### Ingest a URL

```bash
curl -s -X POST http://localhost:9002/api/ingest-http \
  -H "Content-Type: application/json" \
  -d '{
    "input_mode": "url",
    "content": "https://example.com/api/users?id=1"
  }' | jq .
```

### Ingest a curl command

```bash
curl -s -X POST http://localhost:9002/api/ingest-http \
  -H "Content-Type: application/json" \
  -d '{
    "input_mode": "curl",
    "content": "curl -X POST https://example.com/login -d \"user=admin&pass=test\""
  }' | jq .
```

### Ingest a list of URLs

```bash
curl -s -X POST http://localhost:9002/api/ingest-http \
  -H "Content-Type: application/json" \
  -d '{
    "input_mode": "url_file",
    "content": "https://example.com/page1\nhttps://example.com/page2\nhttps://example.com/page3"
  }' | jq .
```

### Ingest a raw HTTP request (base64)

```bash
# Base64-encode a raw HTTP request
REQ_B64=$(printf 'GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n' | base64)

curl -s -X POST http://localhost:9002/api/ingest-http \
  -H "Content-Type: application/json" \
  -d "{
    \"input_mode\": \"burp_base64\",
    \"http_request_base64\": \"$REQ_B64\"
  }" | jq .
```

### Ingest a raw HTTP request with a URL hint (base64)

Raw HTTP requests don't contain the scheme (`https` vs `http`) and the `Host` header alone may not reflect the actual target (e.g. behind a reverse proxy). Provide `url` alongside `http_request_base64` so the parser can resolve the correct scheme and hostname.

```bash
REQ_B64=$(printf 'POST /api/login HTTP/1.1\r\nHost: internal-lb\r\nContent-Type: application/json\r\n\r\n{"user":"admin"}' | base64)

curl -s -X POST http://localhost:9002/api/ingest-http \
  -H "Content-Type: application/json" \
  -d "{
    \"input_mode\": \"burp_base64\",
    \"url\": \"https://app.example.com\",
    \"http_request_base64\": \"$REQ_B64\"
  }" | jq .
```

The `url` field provides the scheme (`https`) and the public hostname (`app.example.com`), overriding whatever `Host` header appeared in the raw request.

### Ingest a HAR file

```bash
curl -s -X POST http://localhost:9002/api/ingest-http \
  -H "Content-Type: application/json" \
  -d "{
    \"input_mode\": \"har\",
    \"content_base64\": \"$(base64 < recording.har)\"
  }" | jq .
```

### Ingest an OpenAPI spec

```bash
curl -s -X POST http://localhost:9002/api/ingest-http \
  -H "Content-Type: application/json" \
  -d "{
    \"input_mode\": \"openapi\",
    \"content_base64\": \"$(base64 < openapi.json)\"
  }" | jq .
```

**Response:**

```json
{
  "project_uuid": "00000000-0000-0000-defa-c01001000001",
  "imported": 15,
  "skipped": 1,
  "format": "openapi",
  "skipped_reasons": {"out_of_scope": 1, "skipped_operation": 2},
  "errors": [],
  "message": "imported 15 requests from OpenAPI spec (1 filtered by scope) (2 operations produced no request)"
}
```

`skipped` is the number of records filtered by scope. `skipped_reasons` counts everything that did not become a record, by reason: `out_of_scope`, `unparsed_line` (URL lists), `skipped_operation` (OpenAPI), `skipped_request` (Postman requests that could not be built, typically an unresolved `{{variable}}` in the URL; each such variable is named in `errors`). `format` is the parser used and `detected_format` is set for `auto`.

OpenAPI security schemes take their credential from `variables`: `bearer` (or the scheme name, or `Authorization`) for `http bearer`, `oauth2` and `openIdConnect`; `basic` as `user:pass` for `http basic`; the parameter name for `apiKey`. A value already starting with `Bearer `/`Basic ` is used as-is.

### Detect the format

```bash
curl -s -X POST http://localhost:9002/api/ingest-http \
  -H "Content-Type: application/json" \
  -d "{
    \"input_mode\": \"auto\",
    \"content_base64\": \"$(base64 < export.json)\"
  }" | jq '.detected_format, .imported'
```

### Ingest into a specific project

Use the `X-Project-UUID` header to scope imported data to a project. If omitted, data is stored under the default project.

```bash
curl -s -X POST http://localhost:9002/api/ingest-http \
  -H "Content-Type: application/json" \
  -H "X-Project-UUID: my-project-uuid" \
  -d '{
    "input_mode": "url",
    "content": "https://example.com/api/users"
  }' | jq .
```

```json
{
  "project_uuid": "my-project-uuid",
  "imported": 1,
  "skipped": 0,
  "message": "imported 1 request from URL"
}
```
