# Vigolium Security Scanner - AI Agent Integration

Vigolium is a web vulnerability scanner available as a CLI tool. Use these commands for security testing workflows.

## Quick Scan Commands

### Scan a single URL
```bash
# Basic GET scan with JSON output
vigolium scan-url https://example.com/api/users --json

# Scan with specific method, body, and headers
vigolium scan-url https://example.com/api/login \
  --method POST \
  --body '{"user":"admin","pass":"test"}' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer TOKEN' \
  --json

# Scan with specific modules only
vigolium scan-url https://example.com/search?q=test -m xss-reflected,sqli-error --json
```

### Scan a raw HTTP request
```bash
# From stdin
echo -e "GET /api/users HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc\r\n\r\n" | \
  vigolium scan-request --json

# From file
vigolium scan-request -i request.txt --json

# With target URL override
vigolium scan-request -i request.txt --target https://staging.example.com --json
```

## Listing Modules

```bash
# List all scanner modules as JSON
vigolium module ls --json

# List only active modules
vigolium module ls --json --type active

# Filter modules by keyword
vigolium module ls xss --json
```

## Ingesting HTTP Traffic

```bash
# Ingest URLs from a file
vigolium ingest -i urls.txt --json

# Ingest from OpenAPI spec
vigolium ingest -i openapi.yaml -t https://api.example.com --json

# Ingest from stdin
cat requests.txt | vigolium ingest --json
```

## Reading Stored Results

```bash
# Survey: metadata only, projected to the keys you need
vigolium finding -j --compact --fields id,severity,url --min-severity high
vigolium traffic -j --compact --fields uuid,url,status_code -n 50

# Select one record exactly (--url is equality; the positional term is a substring search)
vigolium traffic -j --url 'https://example.com/api/v1/me'

# Save a large result to disk instead of into your context; stdout gets a receipt
vigolium finding -j -n 500 -o findings.json

# Extract one message's parts — one call each, no scripting
vigolium traffic body    --uuid "$UUID" -o response.json
vigolium traffic headers --uuid "$UUID" -j
```

Search flags are literal (`%` and `_` are ordinary characters), `--header` and
`--body` each search only their own half of the message, and `--search` spans the
whole exchange.

## JSON Output

All commands support `--json` / `-j` for structured JSON output on stdout. Human-readable messages go to stderr. This makes it safe to parse output in pipelines:

```bash
result=$(vigolium scan-url https://example.com/page --json)
findings=$(echo "$result" | jq '.findings')
count=$(echo "$result" | jq '.findings | length')
```

The **read** commands (`finding`, `traffic`, `db ls`, `db stats`) use a different,
shared envelope: rows are under `.items`, with `.total`, `.offset`, `.limit`,
`.db_path` and `.schema_version` beside them. A failure writes a parseable object
with `.error.code` to stdout and exits non-zero — branch on the code, never on the
message.

```bash
vigolium finding -j -n 100 | jq '.items[] | {id, severity, url}'
```

A read against a `--db` path that does not exist fails `source_missing` (exit 1)
and creates nothing; one pointed at a non-vigolium SQLite file fails
`source_incompatible` (exit 1) without writing tables into it.

## Common Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--json` | `-j` | JSON output to stdout |
| `--modules` | `-m` | Comma-separated module IDs |
| `--concurrency` | `-c` | Worker count (default: 25) |
| `--timeout` | | HTTP timeout (default: 15s) |
| `--proxy` | | HTTP/SOCKS5 proxy URL |
| `--db` | | SQLite database path |
| `--output` | `-o` | On a `-j` read: write the result document to this file, print a receipt |
| `--read-only` | | The database is evidence — the file survives the read byte-identical |
