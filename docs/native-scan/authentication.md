# Authenticated Scanning

Vigolium supports multi-session authenticated scanning via two repeatable flags, `--auth-file` and `--auth`. This enables scanning behind login walls and detecting authorization bypass vulnerabilities (IDOR/BOLA).

Auth files can be written in **YAML or JSON** — the format is auto-detected by file extension (`.json`) or by content sniffing (leading `{` or `[`).

## Quick Start

```bash
# Inline session (simplest)
vigolium scan https://app.com --auth "admin:Cookie:session_id=abc123"

# Single-session file (YAML or JSON)
vigolium scan https://app.com --auth-file ./admin-session.yaml
vigolium scan https://app.com --auth-file ./admin-session.json

# Bare name resolved against scanning_strategy.session.session_dir
vigolium scan https://app.com --auth-file admin-session

# Bundle file with multiple sessions
vigolium scan https://app.com --auth-file ./auth-config.yaml
vigolium scan https://app.com --auth-file ./auth-config.json

# Mix and match — both flags are repeatable
vigolium scan https://app.com --auth-file admin --auth "compare:Cookie:sid=xyz"
```

## The Auth Flags

| Flag | Accepts | Repeatable |
|------|---------|------------|
| `--auth-file <path>` | YAML/JSON file (single session **or** `sessions:` bundle), or a bare name resolved against `scanning_strategy.session.session_dir` | yes |
| `--auth <name:Header:value>` | Inline session — name and header injected as static headers | yes |

If no session is explicitly marked as `primary`, the first session loaded is used as the primary.

With neither flag given, sessions are loaded from the project's
`authentication_hostnames` rows for the target hostnames. A stored session that
carries a **login flow** re-runs that login, rather than reusing the token the
flow produced in an earlier scan — a stored token is usually expired, and a scan
that reused it collected 401s. A stored session with only **static headers**
sends them as-is; there is nothing to re-run.

## Session Roles

Each session has a **role** that determines how it is used during the scan:

- **`primary`** — The main session. Used for discovery, spidering, and as the default requester during the dynamic-assessment phase. There should be exactly one primary session.
- **`compare`** — Comparison sessions for IDOR/BOLA testing. During the dynamic-assessment phase, every request made by the primary session is replayed with each compare session's credentials. If a compare session can access resources it shouldn't, the `authz-compare` module flags it.

## Inline Sessions

The `--auth` flag accepts inline sessions in `name:Header:value` format:

```bash
# Single session with a cookie
vigolium scan https://app.com --auth "admin:Cookie:session_id=abc123"

# Bearer token
vigolium scan https://app.com --auth "user1:Authorization:Bearer eyJhbGciOi..."

# Multiple sessions for IDOR testing
vigolium scan https://app.com \
  --auth "admin:Cookie:session=admin_token" \
  --auth "regular:Cookie:session=user_token"
```

Values containing colons in the `value` part are handled correctly — only the first two colons are used as delimiters.

## Session Files

For sessions with multiple headers or login flows, use files. Both YAML and JSON formats are supported. A file may contain a single session at the top level **or** a `sessions:` list — the loader auto-detects the shape.

### Static Headers

**YAML:**

```yaml
name: admin
role: primary
headers:
  Cookie: "session_id=abc123"
  Authorization: "Bearer mytoken"
```

**JSON:**

```json
{
  "name": "admin",
  "role": "primary",
  "headers": {
    "Cookie": "session_id=abc123",
    "Authorization": "Bearer mytoken"
  }
}
```

Use with:

```bash
vigolium scan https://app.com --auth-file ./admin-session.yaml
vigolium scan https://app.com --auth-file ./admin-session.json
```

Session files are resolved from the configured `session_dir` (default `~/.vigolium/sessions/`) if the path is not absolute. See [Session Strategy Configuration](#session-strategy-configuration) below.

### Login Flows

Session files can define automated login flows. The scanner executes the login request at scan start and extracts credentials from the response.

**YAML:**

```yaml
name: admin
role: primary
login:
  url: "https://app.com/api/auth/login"
  method: POST
  content_type: "application/json"
  body: '{"username":"${ADMIN_USER}","password":"${ADMIN_PASS}"}'
  extract:
    - source: json
      path: "$.token"
      apply_as: "Authorization: Bearer {value}"
```

**JSON:**

```json
{
  "name": "admin",
  "role": "primary",
  "login": {
    "url": "https://app.com/api/auth/login",
    "method": "POST",
    "content_type": "application/json",
    "body": "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}",
    "extract": [
      {
        "source": "json",
        "path": "$.token",
        "apply_as": "Authorization: Bearer {value}"
      }
    ]
  }
}
```

### Multi-Step Login Flows

Use `login.steps` when authentication requires more than one HTTP request. Steps
run in order with a shared cookie jar. To pass a value to a later step, extract
it with `apply_as: "var:<name>"`, then reference it as `{name}` in a later
step's URL or body. The final step must extract at least one credential that
Vigolium can apply to scan requests.

The following provider-backed flow models applications that first receive a
short-lived identity-provider token and then exchange it for an application
token. Stytch B2B password discovery uses this shape: the authenticate response
contains `intermediate_session_token`, and the application exchange endpoint
returns the application's final token.

```yaml
sessions:
  - name: dev_user
    role: primary
    login:
      steps:
        # Step 1: authenticate with the identity provider.
        - url: "https://identity.example.com/passwords/discovery/authenticate"
          method: POST
          content_type: "application/json"
          body: >-
            {"email_address":"${TEST_EMAIL}","password":"${TEST_PASSWORD}"}
          expect:
            status: [200]
            body_contains: "intermediate_session_token"
          extract:
            - source: json
              path: "$.intermediate_session_token"
              apply_as: "var:intermediate_session_token"

        # Step 2: exchange the intermediate token for the app token.
        - url: "https://api.example.com/auth/stytch/exchange"
          method: POST
          content_type: "application/json"
          body: >-
            {"intermediate_session_token":"{intermediate_session_token}"}
          expect:
            status: [200]
            body_contains: "token"
          extract:
            - source: json
              path: "$.token"
              apply_as: "Authorization: Bearer {value}"

            # Keep this rule only when the application also requires a cookie.
            - source: json
              path: "$.token"
              apply_as: "Cookie: token={value}"
```

In a browser trace, calls such as Stytch's `sdk/v1/projects/bootstrap` initialize
the browser SDK and do not produce the authenticated application session. Do
not add them as login steps unless a later authentication request genuinely
depends on a value they return. Likewise, an `/auth/me` request verifies the
finished session; it is not part of the token exchange itself.

Each step may use `expect.status` and `expect.body_contains` to fail early when
the remote service changes behavior. `vigolium auth lint` checks the file's
structure only (including unknown fields, reported with their line); `vigolium
auth load` runs the whole flow, every step and `expect`, before saving the
session, and exits 1 (`login_failed`) without saving it when the login fails.

```bash
vigolium auth lint ./multi-step-token-exchange.yaml
vigolium scan \
  https://app.example.com \
  https://api.example.com \
  --auth-file ./multi-step-token-exchange.yaml \
  --scope-origin strict
```

> **Per-step header limitation:** a multi-step login step currently supports
> `url`, `method`, `content_type`, `body`, `extract`, and `expect`, but not
> arbitrary request headers. Browser SDK endpoints that require Basic auth,
> `Origin`, or SDK-specific headers cannot always be reproduced directly. Use
> an authorized server-side test endpoint or a pre-acquired static token rather
> than putting secrets in the URL.

### Extraction Sources

| Source | Description | Example |
|--------|-------------|---------|
| `json` | Extract a value from the JSON response body using dot-notation. | `path: "$.token"` |
| `cookie` | Extract cookies from `Set-Cookie` response headers. Omit `name` to extract all cookies. | `name: "session_id"` |
| `header` | Extract a value from a response header. | `name: "X-Auth-Token"` |
| `regex` | Extract a capture group from the response body. Group 1 is used by default. | `pattern: 'token="([^"]+)"'` |

The `apply_as` field defines how the extracted value is used. A header template
such as `Authorization: Bearer {value}` applies it to scan requests. In a
multi-step flow, `var:name` stores it for `{name}` substitution in later step
URLs and bodies.

`source: cookie` reads `Set-Cookie` response headers. It cannot observe a cookie
created later by frontend JavaScript. If an exchange endpoint returns a token
in JSON and the frontend turns it into a cookie, extract the JSON value and use
`apply_as: "Cookie: token={value}"` instead.

## Bundle Files

A bundle file defines multiple sessions in one place under a top-level `sessions:` key. Pass it via `--auth-file`.

### YAML Format

```yaml
sessions:
  # Primary session: JSON API login
  - name: admin
    role: primary
    login:
      url: "https://app.com/api/auth/login"
      method: POST
      content_type: "application/json"
      body: '{"username":"${ADMIN_USER}","password":"${ADMIN_PASS}"}'
      extract:
        - source: json
          path: "$.token"
          apply_as: "Authorization: Bearer {value}"

  # Compare session: form-based login
  - name: regular_user
    role: compare
    login:
      url: "https://app.com/login"
      method: POST
      content_type: "application/x-www-form-urlencoded"
      body: "username=${USER_NAME}&password=${USER_PASS}"
      extract:
        - source: cookie

  # Compare session: static API key (no login needed)
  - name: api_key_user
    role: compare
    headers:
      X-API-Key: "${API_KEY}"
```

### JSON Format

```json
{
  "sessions": [
    {
      "name": "admin",
      "role": "primary",
      "login": {
        "url": "https://app.com/api/auth/login",
        "method": "POST",
        "content_type": "application/json",
        "body": "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}",
        "extract": [
          {
            "source": "json",
            "path": "$.token",
            "apply_as": "Authorization: Bearer {value}"
          }
        ]
      }
    },
    {
      "name": "regular_user",
      "role": "compare",
      "login": {
        "url": "https://app.com/login",
        "method": "POST",
        "content_type": "application/x-www-form-urlencoded",
        "body": "username=${USER_NAME}&password=${USER_PASS}",
        "extract": [
          {
            "source": "cookie"
          }
        ]
      }
    },
    {
      "name": "api_key_user",
      "role": "compare",
      "headers": {
        "X-API-Key": "${API_KEY}"
      }
    }
  ]
}
```

Use with:

```bash
vigolium scan https://app.com --auth-file ./auth-config.yaml
vigolium scan https://app.com --auth-file ./auth-config.json
```

### When to Use JSON

JSON is a good choice when:

- **AI agents generate session configs** — most LLMs produce cleaner JSON than YAML, and agent modes (swarm, autopilot) already output session config as JSON natively.
- **Programmatic generation** — scripts, CI pipelines, or tools that build session configs are often simpler in JSON.
- **Embedding in other JSON payloads** — e.g., the REST API `POST /api/agent/run/autopilot` body includes session config as a nested JSON object.

YAML remains convenient for hand-written configs where comments and multi-line strings help readability.

### Format Detection

The format is detected automatically:

1. **File extension** — `.json` files are parsed as JSON; `.yaml` / `.yml` as YAML.
2. **Content sniffing** — if the extension is ambiguous (or missing), content starting with `{` or `[` (after whitespace trimming) is parsed as JSON.
3. **Fallback** — everything else is parsed as YAML.

This means extensionless files work too — pipe JSON directly and it will be detected:

```bash
# Generate config from a script, write to a temp file, scan
./gen-auth-config.sh > /tmp/auth-config
vigolium scan https://app.com --auth-file /tmp/auth-config
```

## Session Config Schema Reference

Both YAML and JSON use the same field names. Here is the full schema:

```
SessionConfig
├── sessions[]              # Array of session definitions
│   ├── name                # (string, required) Unique session name
│   ├── role                # (string) "primary" or "compare"
│   ├── headers             # (map) Static headers, e.g. {"Cookie": "sid=abc"}
│   ├── login               # (object) Automated login flow
│   │   ├── url             # (string) Single-step login endpoint URL
│   │   ├── method          # (string) Single-step HTTP method
│   │   ├── content_type    # (string) Request Content-Type
│   │   ├── body            # (string) Request body
│   │   ├── type            # (string) "bearer" or "cookie" shorthand
│   │   ├── token_path      # (string) Token path used by bearer shorthand
│   │   ├── expect          # (object) status[] and/or body_contains
│   │   ├── extract[]       # (array) Credential extraction rules
│   │   │   ├── source      # (string) "json", "cookie", "header", or "regex"
│   │   │   ├── name        # (string) Cookie/header name to extract
│   │   │   ├── path        # (string) JSON path for json source
│   │   │   ├── pattern     # (string) Pattern for regex source
│   │   │   ├── group       # (int) Regex capture group; defaults to 1
│   │   │   └── apply_as    # (string) Header template or "var:name"
│   │   └── steps[]         # (array) Sequential multi-step flow
│   │       ├── url         # (string, required) Step endpoint URL
│   │       ├── method      # (string, required) Step HTTP method
│   │       ├── content_type # (string) Step request Content-Type
│   │       ├── body        # (string) Supports {name} variables
│   │       ├── expect      # (object) status[] and/or body_contains
│   │       └── extract[]   # (array; required on the final step)
│   ├── login_request       # (string) Raw HTTP request for login (alternative to login)
│   ├── check               # (object) How to tell the session is still logged in
│   │   ├── url             # (string) Protected URL probe; a path resolves against the target origin
│   │   ├── method          # (string) Probe method; default GET
│   │   ├── logged_in       # (object) ALL must hold: status[], body_contains, body_regex, header_regex
│   │   ├── logged_out      # (object) ANY marks logged out: status[], redirect_regex (Location), body_regex
│   │   ├── sample_every    # (int) Evaluate logged_out.body_regex on 1 in N scan responses; default 50
│   │   └── interval        # (duration) Proactive probe at most this often; 0 = only reactive
│   └── reauth              # (object) What a scan does once check finds the session logged out
│       ├── enabled         # (bool) Default true when check is present
│       ├── max_attempts    # (int) Consecutive failed re-logins before giving up; default 3
│       ├── backoff         # (duration) Wait after a failure, doubling each time; default 10s
│       ├── on_failure      # (string) "continue" (default: unauthenticated, phase partial) or "abort"
│       └── pause_traffic   # (bool) Hold this session's requests while re-logging in; default true
```

Only one of `headers`, `login`, or `login_request` can be set per session.

A `login_request` session logs in when the scan starts, like a `login` flow: the raw
request is sent with its own headers, and the credential is discovered from the
response the same way `vigolium auth load` does it (a known token field in a JSON
body becomes `Authorization: Bearer …`, cookies the login set become `Cookie`, and
known auth response headers are copied). A response with none of those fails the
login. The URL comes from the request line, or from `Host` with `https` (or `http`
when the port is 80); write an absolute request line such as
`POST http://localhost:3000/login HTTP/1.1` for a cleartext target on another port.

## Logged-in Check

A session's optional `check` block says what "logged in" looks like on the
target, and `reauth` says what to do once it is not:

```yaml
sessions:
  - name: admin
    role: primary
    login: { ... }
    check:
      url: /api/me                 # a path resolves against the target origin
      method: GET
      logged_in:                   # ALL listed conditions must hold
        status: [200]
        body_contains: '"email"'
        header_regex: '(?i)^content-type: application/json'
      logged_out:                  # ANY match means logged out
        status: [401, 419, 440]
        redirect_regex: '(?i)/(login|signin|sso)\b'
        body_regex: '(?i)(session (has )?expired|please (log|sign) in)'
      sample_every: 50
      interval: 2m
    reauth:
      enabled: true
      max_attempts: 3
      backoff: 10s
      on_failure: continue         # or abort
      pause_traffic: true
```

Durations are Go durations (`90s`, `2m`, `1h30m`); a bare number is seconds.
`header_regex` is matched against each response header written as
`Name: value`. `scanning_strategy.session.validate_url`, `reauth_on_status` and
`reauth_interval` fill `check.url`, `check.logged_out.status` and
`check.interval` for every session that leaves them unset (see
[Session Strategy Configuration](#session-strategy-configuration)).

Validation (`auth lint`, and every loader before a session is used):

- `check.url` must be an `http(s)` URL or a path starting with `/`. It is
  required unless `logged_out` has a `status` or `redirect_regex`.
- Every regex must compile; status codes must be 100-599.
- `sample_every`, `interval`, `max_attempts` and `backoff` must not be
  negative; `on_failure` is `continue` or `abort`.
- Warnings: an empty `logged_in`/`logged_out` block, `logged_in` with no
  `check.url` to evaluate it on, `reauth` with no `check`, and `reauth` on a
  static-header session (nothing to re-run).

The `check` block is used today by `vigolium auth check`. In-scan sampling and
re-login using `check`/`reauth` are not enforced yet: a native scan still logs
in once at start.

### `vigolium auth check`

```bash
vigolium auth check sessions.yaml --url https://app.example.com/account
vigolium auth check admin --url https://app.example.com/api/me -j   # a stored session
vigolium auth check sessions.yaml --session admin                    # uses check.url
```

The argument is a session file (any form `--auth-file` accepts, including a
bare name in `session_dir`) or the name of a session stored with `auth load` in
the current project. It logs each session in exactly as a scan does (the scan's
login transport: `--proxy`, the scan's TLS stance, `--timeout`), then requests
the URL twice through the scan's HTTP stack, with and without the session's
credentials, without following redirects. The URL is `--url`, else
`check.url`, else `validate_url`; a path resolves against the login URL's
origin.

| Verdict | Meaning |
|---------|---------|
| `authenticated` | The session reached what the anonymous request did not (status pair, the anonymous request redirected to a login page or shown a password form, different content), or `check.logged_in` held with credentials and failed without them. |
| `login_wall` | The authenticated request was redirected to a login URL, got a password form, or matched `check.logged_out` by redirect or body. |
| `unauthorized` | 401/403 with credentials, a `check.logged_out` status, or `check.logged_in` failed. |
| `indistinguishable` | Same status and the same body (volatile tokens such as nonces and timestamps ignored) with and without credentials, or `check.logged_in` also held anonymously. Use a page only a logged-in user sees, or configure `check.logged_in`. |
| `error` | The login failed (see `login`) or a request did not complete. |

Exits 0 only when every checked session is `authenticated`. Otherwise exit 1
with error code `login_failed` (a login did not work) or `not_authenticated`
(any other verdict). `-j` prints a read document; each item has `session`,
`url`, `method`, `verdict`, `authenticated`, `reason`, `signals` (`name`,
`side`, `detail`), `similarity`, `auth_response` and `anon_response`
(`status`, `length`, `location`, `error`), and `login` (the `auth load` login
result). A failing run's document carries `ok: false` and the coded `error`.

The database has no columns for `check`/`reauth`, so a stored session is
checked with `--url` (or `validate_url`) and the heuristics only.

## Environment Variables

Session files (both YAML and JSON) support `${VAR}` syntax for secrets. This keeps credentials out of config files:

```bash
export ADMIN_USER=admin
export ADMIN_PASS=s3cret
vigolium scan https://app.com --auth-file ./auth-config.json
```

All `${VAR}` references are expanded from the environment at load time, before format parsing.

## IDOR/BOLA Testing

To test for authorization bypass vulnerabilities, define at least two sessions — one primary and one or more compare sessions.

**YAML:**

```yaml
sessions:
  - name: admin
    role: primary
    headers:
      Cookie: "${ADMIN_SESSION_COOKIE}"

  - name: regular_user
    role: compare
    headers:
      Cookie: "${USER_SESSION_COOKIE}"

  # Optional: unauthenticated session
  - name: unauthenticated
    role: compare
```

**JSON:**

```json
{
  "sessions": [
    {
      "name": "admin",
      "role": "primary",
      "headers": {
        "Cookie": "${ADMIN_SESSION_COOKIE}"
      }
    },
    {
      "name": "regular_user",
      "role": "compare",
      "headers": {
        "Cookie": "${USER_SESSION_COOKIE}"
      }
    },
    {
      "name": "unauthenticated",
      "role": "compare"
    }
  ]
}
```

The built-in `authz-compare` module automatically activates when compare sessions are present. It replays primary session requests with compare session credentials and flags responses that indicate broken access control.

### How Detection Works

1. The primary session makes a request and gets a response (e.g., `GET /api/users/42` -> 200 OK with user data).
2. The same request is replayed with each compare session's credentials.
3. If a compare session also receives a successful response with similar content, the module reports a potential IDOR/BOLA finding with **High** severity.

### Filtering to Auth Modules Only

To run only authorization testing without other active modules:

```bash
vigolium scan https://app.com \
  --auth-file ./auth-config.json \
  --module-tag access-control
```

## How Sessions Affect Scan Phases

| Phase | Session Usage |
|-------|---------------|
| Discovery / Spidering | Primary session only (controlled by `use_in_discovery`) |
| DynamicAssessment | Primary session for main scanning; compare sessions for IDOR/BOLA replay (controlled by `compare_enabled`) |
| KnownIssueScan | Primary session headers (nuclei runs its own HTTP stack and receives the headers directly) |

With `use_in_discovery: false`, Discovery and Spidering run unauthenticated and
DynamicAssessment and KnownIssueScan still authenticate — the setting keeps the
credentials out of discovery, it does not turn authentication off. The
assessment phases send through a view of the same requester, so they share its
connection pool, rate limiter and carried browser sessions but keep their own
cookie jar and response-cache partition.

Compare-session requesters carry the operator's own `-H` headers plus their own
session's credentials, never the primary session's.

In the browser crawl, session cookies keep their Domain/Path and auth headers
are sent only while the crawl stays on a host the scope admits. Each target
reports `auth_state` (`applied` or `failed`, never "verified"); a `failed`
target is crawled unauthenticated unless `spidering.require_auth` /
`--require-auth` makes it fail. See
[Browser policy](../guides/browser-policy.md#credentials-and-scope).

## Validation and Troubleshooting

| Symptom | Meaning and next step |
|---------|-----------------------|
| `auth lint` succeeds but scan hydration fails | Lint validates structure without contacting the login services. Check the failing step's status, response shape, and extraction path. |
| `auth check` says `indistinguishable` | The URL answers the same with and without credentials: it is public, or the server ignores the credentials. Pick a page only a logged-in user sees, or add `check.logged_in` describing it. |
| `auth check` says `login_wall` but `auth load` passed | The login returned a credential, but the app does not accept it on that URL (wrong cookie scope, an extra CSRF/header requirement, or a token for another audience). |
| `auth load` reports `unverified` | The login ran but had no `expect` block, and the response could not confirm it (for example the password form came back). Add `expect.status` / `expect.body_contains` so a wrong password fails. |
| `cookie "token" not found in login response` | The response did not include a matching `Set-Cookie` header. If it returned JSON, use `source: json`; if browser JavaScript creates the cookie, build the `Cookie` header with `apply_as`. |
| A later request still contains `{name}` | The earlier rule did not use `apply_as: "var:name"`, or its extraction path did not match. Variable names are case-sensitive. |
| `last step must have at least one extract rule` | Add a final extraction that produces an application header or cookie. Intermediate variables alone are not scan credentials. |
| The banner prints a scan ID, then `session initialization failed` | The scan stopped before discovery or assessment. The scan ID does not mean findings were produced. |
| Requests include another environment | Use `--scope-origin strict`, especially when the active project already contains records from several environments. |

Do not print response bodies while debugging production credentials. Prefer a
dedicated test account and rotate credentials that have appeared in shell
history, logs, or support transcripts.

## Login Request Lifecycle

A login request goes to the host the scan is about to attack, so it is treated
as target traffic:

- It follows `--proxy` (and `HTTP_PROXY` / `HTTPS_PROXY`), resolved exactly as
  the scan's own requests are, with an explicit proxy URL so a `localhost`
  target is proxied too. A proxy log therefore shows the login alongside the
  scan it authenticated.
- It accepts self-signed, expired and wrong-host certificates, like every other
  request to the target.
- It is cancellable: Ctrl-C during setup aborts the in-flight login instead of
  waiting out its timeout.

Two bounds apply. Each login request has its own 30s timeout, and **all** login
flows together — every session, every step — share a total budget of 2 minutes.
A flow that exceeds the total fails naming the session and step it stopped on,
rather than letting six three-step flows spend nine silent minutes before the
first scan request.

When a login fails and the scan continues anyway (`--auth-best-effort`, or a
session loaded from the database), DynamicAssessment prints
`configured authentication could not be applied — assessment runs
unauthenticated` and the phase is recorded as partial with the reason
`auth_unavailable`, plus `login_budget`, `cancelled` or `scan_budget` naming the
cause. See [Scan completeness](../api-references/scan.md#scan-completeness).

## Current Authentication Limitations

- Login flows are hydrated once during scan initialization. The session
  `check`/`reauth` blocks (and their `scanning_strategy.session` defaults) are
  validated and drive `vigolium auth check`, but a native scan does not yet
  sample traffic or re-login with them. Ensure a token's lifetime covers the
  scan or divide a long scan into shorter runs.
- Pass multi-step configurations directly with `--auth-file`. `vigolium auth
  load` currently validates and persists only single-step login fields, so a
  stored multi-step flow will not round-trip correctly.
- Multi-step variables are substituted only in subsequent step URLs and bodies.
  Arbitrary per-step headers are not part of the current schema.

## Session Strategy Configuration

Session behavior is configured under `scanning_strategy.session` in `vigolium-configs.yaml` (see `public/vigolium-configs.example.yaml` for the full annotated example).

```yaml
scanning_strategy:
  session:
    # Directory where session files are stored.
    # When --auth-file receives a bare name (e.g. "myapp"), the scanner
    # resolves it as <session_dir>/myapp.yaml (or .yml, .json).
    # Default: ~/.vigolium/sessions/
    session_dir: ~/.vigolium/sessions/

    # Apply primary session headers during discovery and spidering phases.
    # When false, those phases run unauthenticated and credentials are only
    # used during the dynamic-assessment phase.
    # Default: true
    use_in_discovery: true

    # Enable cross-session IDOR/BOLA replay with compare sessions.
    # When true and multiple sessions are defined, the authz-compare module
    # replays primary-session requests with each compare session's credentials.
    # When false, compare sessions are ignored even if defined.
    # Default: true
    compare_enabled: true

    # Defaults for every session's `check` block: each fills the value a
    # session leaves unset (a session's own value always wins).
    # check.interval: proactive logged-in probe at most this often ("2m").
    reauth_interval: ""

    # check.logged_out.status: statuses that mean "logged out" (e.g. [401, 440]).
    reauth_on_status: []

    # check.url: the protected URL `vigolium auth check` probes when --url is
    # not given. A path resolves against the target origin.
    validate_url: ""
```

### Field Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `session_dir` | string | `~/.vigolium/sessions/` | Directory for session file lookup. `--auth-file myapp` (bare name) resolves to `<session_dir>/myapp.yaml` (tries `.yaml`, `.yml`, `.json` in order). Supports `~` expansion. |
| `use_in_discovery` | bool | `true` | When `true`, the primary session's headers are injected into the requester used for discovery and spidering. When `false`, those phases run unauthenticated — useful for mapping the public attack surface first, then scanning authenticated. |
| `compare_enabled` | bool | `true` | When `true`, compare sessions are created and the `authz-compare` module is activated for IDOR/BOLA testing. When `false`, compare sessions are ignored even if defined — handy when you only need authenticated scanning without authorization comparison. |
| `reauth_interval` | duration | `""` | Default `check.interval` for sessions that do not set one. Must parse as a Go duration. |
| `reauth_on_status` | []int | `[]` | Default `check.logged_out.status` for sessions that do not set one. |
| `validate_url` | string | `""` | Default `check.url`: an `http(s)` URL or a `/path`. `vigolium auth check` uses it when `--url` is not given. |

These three are defaults for the [logged-in check](#logged-in-check). In-scan
sampling and re-login are not enforced yet.

### Session Directory Resolution

When `--auth-file` receives a bare name (no path separators, no extension, fewer than 3 colon-separated parts), the scanner resolves it from `session_dir`. Extensions are tried in order: `.yaml`, `.yml`, `.json`.

```bash
# These are all equivalent when session_dir is ~/.vigolium/sessions/
vigolium scan https://app.com --auth-file myapp
vigolium scan https://app.com --auth-file ~/.vigolium/sessions/myapp.yaml
vigolium scan https://app.com --auth-file ~/.vigolium/sessions/myapp.json
```

If the bare name has no matching file with any extension, `.yaml` is appended as the default. Absolute paths and relative paths with directory separators (e.g. `./sessions/myapp.json`) bypass `session_dir` and are used as-is.

To change the lookup directory:

```yaml
scanning_strategy:
  session:
    session_dir: /opt/vigolium/shared-sessions/
```

### Common Patterns

**Unauthenticated discovery, authenticated scanning:**

```yaml
scanning_strategy:
  session:
    use_in_discovery: false
```

Crawls the public-facing site first, then applies session headers only during the dynamic-assessment phase. This is useful when you want to see what an unauthenticated attacker can discover before testing the authenticated surface.

**Authenticated scanning without IDOR testing:**

```yaml
scanning_strategy:
  session:
    compare_enabled: false
```

Useful when you only need to scan behind a login wall but don't have multiple user roles to compare. The primary session's credentials are applied to all phases, but no compare requesters are created and the `authz-compare` module stays inactive.

**Team shared sessions directory:**

```yaml
scanning_strategy:
  session:
    session_dir: /shared/team/vigolium-sessions/
```

Point all team members to a shared directory so `--auth-file staging-admin` resolves the same file for everyone.

Scanning profiles (`~/.vigolium/profiles/`) can also override session strategy values — useful for having a "quick unauthenticated" profile alongside a "deep authenticated" profile.

## Using Session Config with Agent Modes

Agent modes (`swarm`, `autopilot`) can prepare authentication from source
analysis or explicit credentials. Swarm persists generated native-session
configuration as `auth-config.yaml` in its session directory.

With `--source`, Swarm can discover login flows and feed the generated config
into recon, discovery, and native scanning automatically.

Swarm's equivalent of native `--auth-file` is `--auth-config`:

```bash
# Swarm with pre-configured auth
vigolium agent swarm \
  --target https://app.com \
  --auth-config ./auth-config.yaml
```

## Examples

### Scan a REST API with Bearer Token

```bash
vigolium scan https://api.example.com \
  --auth "admin:Authorization:Bearer eyJhbG..."
```

### Scan with Cookie-Based Auth

```bash
vigolium scan https://app.example.com \
  --auth "user:Cookie:PHPSESSID=abc123; csrftoken=xyz"
```

### Full IDOR Test with Login Automation (YAML)

```bash
export ADMIN_USER=admin ADMIN_PASS=admin123
export USER_NAME=user1 USER_PASS=user123

vigolium scan https://app.example.com \
  --auth-file ./auth-config.yaml \
  --module-tag access-control
```

### Full IDOR Test with Login Automation (JSON)

```bash
export ADMIN_USER=admin ADMIN_PASS=admin123
export USER_NAME=user1 USER_PASS=user123

vigolium scan https://app.example.com \
  --auth-file ./auth-config.json \
  --module-tag access-control
```

### Combine with Other Scan Options

Auth flags work with all other scan options:

```bash
vigolium scan https://app.example.com \
  --auth-file ./auth-config.json \
  --strategy lite \
  --only dynamic-assessment \
  --concurrency 10 \
  --format html -o report.html
```

### One-Liner JSON Auth Config

For quick testing or CI scripts, you can write a JSON config inline:

```bash
echo '{"sessions":[{"name":"admin","role":"primary","headers":{"Authorization":"Bearer '"$TOKEN"'"}}]}' > /tmp/auth.json
vigolium scan https://app.com --auth-file /tmp/auth.json
```

### Agent-Generated Session Config

When an AI agent discovers auth flows in source code, it produces JSON like:

```json
{
  "sessions": [
    {
      "name": "default_user",
      "role": "primary",
      "login": {
        "url": "https://app.com/api/login",
        "method": "POST",
        "content_type": "application/json",
        "body": "{\"email\":\"test@test.com\",\"password\":\"testpassword\"}",
        "extract": [
          {
            "source": "json",
            "path": "$.token",
            "apply_as": "Authorization: Bearer {value}"
          }
        ]
      }
    }
  ]
}
```

This can be saved and reused across scans:

```bash
vigolium scan https://app.com --auth-file ./agent-generated-auth.json
```
