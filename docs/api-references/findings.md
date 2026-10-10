# Vigolium API Reference — Findings

## GET /api/findings — List Findings

Returns paginated vulnerability findings.

**Query parameters:**

| Parameter     | Type   | Default    | Description                                       |
|---------------|--------|------------|---------------------------------------------------|
| `limit`       | int    | 50         | Number of findings to return (max 500)            |
| `offset`      | int    | 0          | Offset for pagination                             |
| `domain`      | string |            | Filter by hostname (supports `*` wildcards)       |
| `severity`    | string |            | Filter by severity (comma-separated): `critical`, `high`, `medium`, `low`, `suspect`, `info` |
| `scan_uuid`     | string |            | Filter by scan UUID                               |
| `module_name` | string |            | Filter by module name                             |
| `module_type`    | string |            | Exact module-type filter, including `active`, `passive`, `nuclei`, `agent`, `oast`, `extension`, `known-issue-scan`, or `whitebox` |
| `finding_source` | string |            | Exact source filter, including `dynamic-assessment`, `known-issue-scan`, `agent`, `autopilot`, `oast`, `extension`, `audit`, `import`, or `spidering` |
| `record_kind` | string | `finding` | Comma-separated `finding`, `candidate`, or `observation` |
| `repo_name`   | string |            | Filter by repository name or URL (exact match). Populated for audit findings |
| `status`      | string |            | Filter by lifecycle status (comma-separated): `draft`, `triaged`, `confirmed`, `false_positive`, `accepted_risk`, `fixed` |
| `search`      | string |            | Search across description, module ID, matched_at  |
| `sort`        | string | `found_at` | Sort field: `found_at`, `created_at`, `severity`, `module_name`, `module_id`, `confidence` |
| `order`       | string | `desc`     | Sort order: `asc` or `desc`                       |

```bash
# List all findings
curl -s http://localhost:9002/api/findings | jq .

# Filter by severity
curl -s 'http://localhost:9002/api/findings?severity=critical,high' | jq .

# Filter by domain and module
curl -s 'http://localhost:9002/api/findings?domain=example.com&module_name=xss' | jq .

# Filter by module type
curl -s 'http://localhost:9002/api/findings?module_type=passive' | jq .

# Filter by finding source
curl -s 'http://localhost:9002/api/findings?finding_source=dynamic-assessment' | jq .

# Filter by lifecycle status
curl -s 'http://localhost:9002/api/findings?status=triaged,fixed' | jq .

# Filter by repo name (audit findings)
curl -s 'http://localhost:9002/api/findings?finding_source=audit&repo_name=Kong/kong' | jq .

# Search findings
curl -s 'http://localhost:9002/api/findings?search=reflected' | jq .
```

```json
{
  "project_uuid": "my-project-uuid",
  "data": [
    {
      "id": 1,
      "project_uuid": "my-project-uuid",
      "http_record_uuids": ["abc-123"],
      "scan_uuid": "scan-456",
      "url": "https://example.com/search?q=test",
      "hostname": "example.com",
      "module_id": "xss-scanner",
      "module_name": "XSS Scanner",
      "module_type": "active",
      "module_short": "Detects reflected cross-site scripting via parameter injection",
      "finding_source": "dynamic-assessment",
      "description": "Reflected XSS via parameter 'q'",
      "severity": "high",
      "confidence": "firm",
      "tags": ["xss", "reflected"],
      "status": "triaged",
      "remediation": "Escape user input before rendering it in HTML context.",
      "cwe_id": "CWE-79",
      "cvss_score": 7.5,
      "source_file": "",
      "repo_name": "",
      "matched_at": ["https://example.com/search?q=test"],
      "extracted_results": ["<script>alert(1)</script>"],
      "finding_hash": "e3b0c44298fc1c14",
      "found_at": "2026-02-16T15:05:00Z",
      "created_at": "2026-02-16T15:05:00Z"
    }
  ],
  "total": 42,
  "limit": 50,
  "offset": 0,
  "has_more": false
}
```

> **Note:** The list response excludes the heavy fields `request`, `response`, and `additional_evidence` for performance. Use `GET /api/findings/:id` to fetch a finding with its full evidence payload.

---

## GET /api/findings/:id — Get Finding Detail

Returns a single finding by its numeric ID, including the full `request`, `response`, and `additional_evidence` payloads.

```bash
curl -s http://localhost:9002/api/findings/1 | jq .
```

```json
{
  "id": 1,
  "project_uuid": "my-project-uuid",
  "http_record_uuids": ["abc-123"],
  "scan_uuid": "scan-456",
  "url": "https://example.com/search?q=test",
  "hostname": "example.com",
  "module_id": "xss-scanner",
  "module_name": "XSS Scanner",
  "module_type": "active",
  "module_short": "Detects reflected cross-site scripting via parameter injection",
  "finding_source": "dynamic-assessment",
  "description": "Reflected XSS via parameter 'q'",
  "severity": "high",
  "confidence": "firm",
  "tags": ["xss", "reflected"],
  "status": "triaged",
  "remediation": "Escape user input before rendering it in HTML context.",
  "cwe_id": "CWE-79",
  "cvss_score": 7.5,
  "source_file": "",
  "repo_name": "",
  "matched_at": ["https://example.com/search?q=test"],
  "extracted_results": ["<script>alert(1)</script>"],
  "additional_evidence": [
    "GET /search?q=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E HTTP/1.1\r\nHost: example.com\r\n\r\n\n---------\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n..."
  ],
  "request": "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\r\nHost: example.com\r\n\r\n",
  "response": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n...",
  "finding_hash": "e3b0c44298fc1c14",
  "found_at": "2026-02-16T15:05:00Z",
  "created_at": "2026-02-16T15:05:00Z"
}
```

**Error responses:**

| Code | Condition                      |
|------|--------------------------------|
| 400  | Invalid ID (not a number)      |
| 404  | Finding not found              |
| 503  | Database unavailable           |

---

## PATCH /api/findings/:id/status — Update Finding Status

Operator and admin users can update a finding's lifecycle state. The lookup is
scoped to `X-Project-UUID`; a finding from another project returns `404`.

```bash
curl -s -X PATCH http://localhost:9002/api/findings/42/status \
  -H 'Content-Type: application/json' \
  -d '{"status":"false_positive"}' | jq .
```

Accepted values are `draft`, `triaged`, `confirmed`, `false_positive`,
`accepted_risk`, and `fixed`.

---

## POST /api/findings/:id/verify — Verify a Finding

`vigolium finding verify` over REST (operator and admin). Re-runs the module
behind one finding against the request it originally scanned and records
whether it reproduces. `:id` is the numeric ID or the finding hash (12+
character prefix); the lookup is scoped to `X-Project-UUID`, so a finding from
another project returns `404` (`error_code: finding_not_found`). The call is
synchronous: it answers when the module run ends.

| Verdict          | Meaning |
|------------------|---------|
| `confirmed`      | the module reported the same finding again |
| `not_reproduced` | the module ran against a responding target and did not |
| `inconclusive`   | target unreachable, module timed out or failed, or the baseline could not be reconstructed |
| `unsupported`    | no deterministic re-run (agent, audit, OAST and known-issue-scan findings; an `ext-*` module the project's extension config does not load) |

**Request body (optional):**

| Field        | Type   | Description |
|--------------|--------|-------------|
| `dry_run`    | bool   | Return the reconstruction (module, baseline, insertion point); send and write nothing |
| `no_write`   | bool   | Run, but do not store the verdict |
| `mark`       | bool   | Also set the status: `not_reproduced` → `false_positive`, `confirmed` → `confirmed` (not with `dry_run`/`no_write`) |
| `refetch`    | bool   | Passive findings: fetch a fresh response instead of re-analyzing the stored one |
| `rate_limit` | number | Max requests/second (0 = unlimited; fractions allowed) |
| `timeout`    | string | Go duration bounding the run (default `2m`, at most `10m`; one request is capped at 15s) |

```bash
curl -s -X POST http://localhost:9002/api/findings/42/verify \
  -H 'Content-Type: application/json' \
  -d '{"mark":true}' | jq .
```

**Response (v1):** the result object, the item `vigolium finding verify -j`
emits:

```json
{
  "id": 42,
  "finding_hash": "3f9a0c2b71de…",
  "module_id": "sqli-error-based",
  "verdict": "confirmed",
  "plan": {"baseline": {"source": "origin_record", "method": "GET", "url": "http://app.local/item?id=1"}, "insertion_point": {"type": "URL_PARAM", "name": "id"}, "network": true},
  "results": 1,
  "matched": 1,
  "requests": 14,
  "duration_ms": 812,
  "written": true,
  "status_change": {"id": 42, "from": "triaged", "to": "confirmed"}
}
```

With `Vigolium-Api-Version: 2` the body is the list envelope (`kind:
"mutation"`, `items: [result]`) with `changed`, `action: "verify"`,
`dry_run`, `written` and a `verdicts` tally.

| Status | Description |
|--------|-------------|
| 200    | Verified (any verdict) |
| 400    | Invalid option, or an ambiguous hash prefix |
| 404    | Finding not found in the selected project |
| 503    | Database not configured |

---

## DELETE /api/findings/:id — Delete Finding

Deletes a single finding by its numeric ID. Associated `finding_records` junction rows, `finding_observations` and `finding_status_events` rows are also removed.

```bash
curl -s -X DELETE http://localhost:9002/api/findings/42 | jq .
```

**Response:**

```json
{
  "message": "finding deleted",
  "id": 42
}
```

| Status | Description              |
|--------|--------------------------|
| 200    | Finding deleted          |
| 400    | Invalid ID (not a number)|
| 404    | Finding not found        |
| 503    | Database not configured  |

---

## Finding Fields

### `status`

**Type:** `string` (optional; database default `triaged`)

Lifecycle state of the finding. Deterministic native findings normally arrive
as `triaged`; AI-generated, audit, and imported candidates normally arrive as
`draft`. Update via `PATCH /api/findings/:id/status` and filter on the list
endpoint with `?status=`.

### `remediation`, `cwe_id`, `cvss_score`

Optional classification fields populated by modules and the agent triage pipeline. `cvss_score` is a float (0–10); `cwe_id` is a CWE identifier (e.g. `CWE-79`); `remediation` is a free-form recommendation string.

### `repo_name`

**Type:** `string` (optional, omitted when empty)

The repository name or URL associated with a finding. Primarily populated for audit findings. During audit import, the value is resolved with the following priority:

1. `repo_url` field in `audit-state.json` (if present)
2. `repo` field in `audit-state.json` (if present)
3. `**Repository**:` line from `commit-recon-report.md` — prefers a full URL in parentheses (e.g. `https://github.com/goharbor/harbor`), otherwise uses the org/repo slug (e.g. `Kong/kong`)
4. Folder basename as fallback

Use the `?repo_name=` query parameter on `GET /api/findings` to filter findings by repository.

### `additional_evidence`

**Type:** `string[]` (optional, omitted when empty)

Stores extra HTTP request/response pairs associated with a finding. Each entry is a single string containing a raw request and raw response separated by the delimiter `\n---------\n`.

This field is populated in two ways:

1. **Modules and extensions** — A module or JS extension can attach supplementary evidence when creating a finding (e.g., multiple payloads tried, confirmation requests, or baseline comparisons).
2. **Deduplication** — When duplicate findings are merged (same `module_id`, `severity`, and `matched_at` URL), the `request`/`response` pairs from the removed duplicates are automatically collected into the surviving finding's `additional_evidence`.

**Example entry format:**

```
GET /api?id=1'+OR+1=1 HTTP/1.1\r\nHost: example.com\r\n\r\n
---------
HTTP/1.1 500 Internal Server Error\r\n\r\n{"error":"syntax error"}
```

To parse an entry, split on `\n---------\n` — the first part is the request, the second is the response.
