---
id: swarm-source-format-routes
name: Format Route Analysis Results
description: Convert route analysis notes into JSONL HTTP records
output_schema: source_analysis
variables:
  - TargetURL
  - Hostname
---

You are given notes from a source code analysis documenting HTTP routes and endpoints. Convert these notes into structured JSONL HTTP records.

## Output Format

Output **all routes** as **JSONL** (one JSON object per line) wrapped in a ` ```jsonl ` fenced code block. Each line is a standalone HTTP record.

```jsonl
{"method":"GET","url":"{{.TargetURL}}/api/products?q=test&page=1","headers":{},"notes":"List products — uses raw SQL query (sqli sink)"}
{"method":"POST","url":"{{.TargetURL}}/api/endpoint","headers":{"Content-Type":"application/json"},"body":"{\"param\":\"value\",\"name\":\"test\"}","notes":"Description of endpoint and relevant sinks"}
{"method":"PUT","url":"{{.TargetURL}}/api/users/1","headers":{"Content-Type":"application/json"},"body":"{\"name\":\"test\",\"email\":\"user@test.com\"}","notes":"Update user by ID — requires auth"}
{"method":"DELETE","url":"{{.TargetURL}}/api/items/1?force=true","headers":{},"notes":"Delete item — admin only"}
```

Two things the examples can't show: `body` is an escaped JSON *string*, never
a nested object, and every route carries its parameters — a `body` with the
fields its handler reads for POST/PUT/PATCH, query parameters in the URL for
GET/DELETE.
