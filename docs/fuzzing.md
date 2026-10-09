# Fuzzing (`vigolium fuzz`)

`vigolium fuzz` is a low-level, agent-driven fuzzing **primitive**. It injects a
payload set **you supply** into positions **you pick** in a single HTTP request,
sends each variant, and reports per-payload response signals with match/filter
gating and auto-calibration.

## Mental model — primitive, not scanner

`fuzz` makes **no** vulnerability decision and emits **no** findings. It sends
exactly what you tell it and shows you exactly what came back. The intelligence
lives in the caller (you, or a coding agent).

> The native scan **decides what to test and judges the result.** `fuzz` does
> neither — it sends what you say and shows you what came back.

Use the right tool:

| Goal | Use |
|------|-----|
| Find **known** vuln classes (XSS/SQLi/LFI/SSRF…) with confirmation + low FPs | `vigolium scan-request -i req.txt -m xss,sqli -j` |
| Send **custom payloads** at an **exact position** and read raw anomalies | `vigolium fuzz …` |
| Wordlist-scale **content/param discovery** | `vigolium fuzz … -w dir-short` |

`fuzz` will happily show you 500s and size deltas that aren't bugs — interpreting
them is your job. That is the deliberate trade for control and transparency.

## Sources

Provide the request one of these ways (or pipe it on stdin):

```bash
vigolium fuzz 'https://acme.test/item?id=FUZZ'        # positional URL (+ -X/-H/-d)
vigolium fuzz -i req.txt                               # curl / raw HTTP / Burp / base64 / URL
vigolium fuzz -u <record-uuid>                         # a stored HTTP record
cat req.txt | vigolium fuzz --target http://acme.test  # stdin (scheme-less raw → use --target)
```

## Positions — what to fuzz

- A literal **`FUZZ` marker** anywhere in the request (request line, path,
  header, body) wins if present. Occurrences in the request line are
  auto-encoded, so a payload with spaces (`' OR '1'='1`) stays well-formed.
  Rename the keyword with `--keyword`.
- Otherwise `--fuzz method|path|params|param-name|headers|cookies|all`
  (default: **all** discovered insertion points).
- Or target one point: `--point URL_PARAM:id`, or `--fuzz-header X-Forwarded-For`.

## Payloads — combine freely

```bash
--class sqli,xss,lfi,ssrf,cmdi,ssti,xxe,open_redirect,crlf,path_traversal
-w/--wordlist <builtin|file>     # builtins: fuzz, dir-short, dir-long, file-short, file-long
-p/--payload '<literal>'          # inline, repeatable
```

Classes come from the shared `pkg/payloads` catalog (the same set behind the JS
`vigolium.payloads()` API); aliases like `traversal`, `rce`, `redirect` resolve.

## Anomaly gating

Matchers **keep** a response (OR across categories; empty = keep all); excludes
**drop** it (OR):

```
--match-status-code 200,301   --match-size N    --match-words N    --match-lines N
--match-regex <re>            --match-time <ms>
--exclude-status-code 404     --exclude-size N  --exclude-words N  --exclude-lines N
--exclude-regex <re>          --exclude-time <ms>
```

`--match-status-code all` keeps every status. **Auto-calibration** is on by default: `fuzz`
sends a few improbable values first, learns the target's wildcard/catch-all
`(status,length)` signature, and suppresses matching results (surfaced as
`"calibrated": true`, never silently hidden). Disable with `--no-calibrate`.

## Output

Default: a human table, one line per send, to stdout — matched results only
unless `--all-results`. `--format jsonl` prints the per-payload stream instead,
one self-describing object per send:

```json
{"position":"id","position_type":"URL_PARAM","payload":"' OR '1'='1","status":500,
 "length":73,"words":15,"lines":0,"reflected":true,"status_changed":true,
 "length_delta":48,"matched":true}
```

`-o file` writes that stream to a file; stdout keeps the table (or the `-j`
envelope).

### Agent JSON contract (`-j/--json`)

With the global `-j`, `fuzz` prints **one envelope** on **stdout** — a usable
handle so you don't parse the stream. The ranked top results are `items`, the
run summary sits beside them, and `total` is the full matched count:

```json
{
  "schema_version": 1, "command": "fuzz", "kind": "read", "ok": true,
  "target": "https://acme.test",
  "positions": 1, "payloads": 13,
  "sent": 13, "matched": 1, "calibrated": 8, "errors": 0,
  "baseline": {"status": 200, "length": 25, "words": 4, "lines": 0},
  "total": 1, "offset": 0, "limit": 1,
  "items": [ { "payload": "' OR '1'='1", "status": 500, "reflected": true, "matched": true } ],
  "query": "vigolium scan-request -i 'https://acme.test/item?id=FUZZ' -m xss,sqli,lfi,ssrf,cmdi -j",
  "query_argv": ["vigolium", "scan-request", "-i", "https://acme.test/item?id=FUZZ", "-m", "xss,sqli,lfi,ssrf,cmdi", "-j"]
}
```

The per-payload stream is not written under `-j` unless `-o` names a file;
`-j --format jsonl` without `-o` is a usage error (exit 2), since both would
claim stdout. The old local `--pretty` is a deprecated no-op (the table is the
default); `--pretty` now means the global "indent -j output".

`items` are ranked most-interesting first (status-changed → reflected →
largest size delta → slowest). `query` (or `query_argv`, ready for exec) is a
confirmation command against the hardened module scanner.

`--fail-on-match` exits non-zero (**3**) when any result matches — for CI/agent
gating. Network policy honors `HTTP_PROXY`/`HTTPS_PROXY` (route through Burp).

## Recipes

```bash
# SQLi class at a URL param, keep 500s
vigolium fuzz 'https://acme.test/item?id=FUZZ' --class sqli --match-status-code 500

# One exact point, custom wordlist, drop 404s (auto-calibrated)
vigolium fuzz -i req.txt --point URL_PARAM:id -w /list/sqli.txt --exclude-status-code 404

# Content discovery on a path segment
vigolium fuzz 'https://acme.test/FUZZ' -w dir-short --match-status-code 200,301,403

# Method (verb) fuzzing
vigolium fuzz 'https://acme.test/admin' --fuzz method -p PUT -p DELETE --match-status-code all

# Agent gate: LFI via header, regex-match /etc/passwd, non-zero on hit
vigolium fuzz -i req.txt --fuzz-header X-Api-Version --class lfi --match-regex 'root:.*:0:0' --fail-on-match

# Agent summary
vigolium fuzz 'https://acme.test/item?id=FUZZ' --class sqli,xss --match-status-code 500 -j
```

## Relationship to `replay`

`replay` re-sends a request and diffs baseline vs replay (including bulk
pattern-search re-send of stored traffic, and exact-byte `--raw-request`
overrides); `fuzz` is payload/wordlist-scale fuzzing with anomaly gating. All
payload / insertion-point fuzzing lives in `fuzz` — `replay` has no `--mutate`
flag. Both share the same `pkg/replay` send library; the agent's in-process
`replay_request` tool still supports mutations and is unchanged.
