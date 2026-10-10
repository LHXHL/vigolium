package httpmsg

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/vigolium/vigolium/internal/redact"
)

// CurlOptions shapes a ToCurl rendering.
type CurlOptions struct {
	// Insecure adds -k (skip TLS verification).
	Insecure bool
	// RedactAuth replaces the value of every credential-bearing header
	// (redact.HeaderNames: Authorization, Cookie, X-API-Key, …) with
	// redact.Placeholder. Off by default: a replay usually needs the session.
	RedactAuth bool
	// Proxy adds -x <proxy>.
	Proxy string
	// HTTP2 forces --http2 even when the request line does not say HTTP/2
	// (a record whose stored version is h2 but whose raw bytes are h1-shaped).
	HTTP2 bool
}

// CurlCommand is one rendered curl invocation.
type CurlCommand struct {
	// Command is the POSIX-sh command line. Every argument is single-quoted
	// where needed, so it is safe to paste or to run with `sh -c`.
	Command string
	// Argv is the same invocation as an argv vector, curl first, for exec.
	Argv []string
	// StdinBase64 is set when the body is not printable text: Argv then reads
	// the body from stdin (--data-binary @-) and Command pipes these bytes in
	// (printf '%s' <b64> | base64 --decode | curl …). A caller exec'ing Argv
	// must write the decoded bytes to curl's stdin.
	StdinBase64 string
	// Credentials reports that the request carries a credential header, so a
	// caller can warn before printing it.
	Credentials bool
	// Redacted reports that at least one credential header was replaced.
	Redacted bool
}

// ErrCurlNoTarget is returned when neither the target URL nor an absolute-form
// request line names where the request goes.
var ErrCurlNoTarget = errors.New("no target URL: the request's scheme/host/port are unknown")

// curlDroppedHeaders are recomputed by curl from what it actually sends;
// passing the stored value would contradict it. Transfer-Encoding is dropped
// because the stored body already carries its chunk framing and curl would
// chunk it a second time.
var curlDroppedHeaders = map[string]bool{
	"content-length":    true,
	"transfer-encoding": true,
}

// curlSafeArg is the set of arguments that need no quoting in POSIX sh.
var curlSafeArg = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)

// ToCurl renders a raw HTTP request as a curl command.
//
// targetURL supplies the scheme, host and port (scheme://host[:port], any path
// is ignored): the stored record's own fields, never the Host header alone,
// which would send an https request over http. The request target, headers
// and body come from raw. A Host header that matches the URL authority is
// dropped (curl sends it); a different one is kept, so a virtual-host request
// stays faithful.
//
// Bodies that are printable text go inline as --data-binary '<body>' (POSIX
// single quotes, so no shell expansion); anything else goes through a base64
// pipe into --data-binary @- (see CurlCommand.StdinBase64).
func ToCurl(raw []byte, targetURL string, o CurlOptions) (CurlCommand, error) {
	if len(raw) == 0 {
		return CurlCommand{}, errors.New("empty request")
	}
	lines, _, bodyStart, err := ExtractAllHeaders(raw)
	if err != nil {
		return CurlCommand{}, fmt.Errorf("parse request: %w", err)
	}
	if len(lines) == 0 {
		return CurlCommand{}, errors.New("no request line")
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 2 {
		return CurlCommand{}, fmt.Errorf("malformed request line %q", lines[0])
	}
	method, target := fields[0], fields[1]
	version := ""
	if len(fields) > 2 {
		version = strings.ToUpper(fields[2])
	}

	scheme, authority, target, err := curlTarget(targetURL, target)
	if err != nil {
		return CurlCommand{}, err
	}
	fullURL := scheme + "://" + authority + target

	argv := []string{"curl", "-sS"}
	var headerArgs []string
	var out CurlCommand
	compressed := false
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		if !ok || name == "" || strings.HasPrefix(name, ":") {
			continue // blank line or an h2 pseudo-header
		}
		value = strings.TrimSpace(value)
		lower := strings.ToLower(name)
		if curlDroppedHeaders[lower] {
			continue
		}
		if lower == "host" && sameAuthority(value, scheme, authority) {
			continue
		}
		if lower == "accept-encoding" {
			compressed = true
		}
		if _, sensitive := redact.HeaderNames[lower]; sensitive && value != "" {
			out.Credentials = true
			if o.RedactAuth {
				value = redact.Placeholder
				out.Redacted = true
			}
		}
		headerArgs = append(headerArgs, "-H", name+": "+value)
	}

	var body []byte
	if bodyStart > 0 && bodyStart < len(raw) {
		body = raw[bodyStart:]
	}

	switch {
	case method == "HEAD" && len(body) == 0:
		argv = append(argv, "-I")
	case len(body) > 0 && method != "POST",
		len(body) == 0 && method != "GET":
		argv = append(argv, "-X", method)
	}
	if version == "HTTP/2" || version == "HTTP/2.0" || o.HTTP2 {
		argv = append(argv, "--http2")
	}
	if needsPathAsIs(target) {
		argv = append(argv, "--path-as-is")
	}
	if strings.ContainsAny(fullURL, "[]{}") {
		// curl globs [] and {} in URLs; a stored URL is literal.
		argv = append(argv, "-g")
	}
	if compressed {
		argv = append(argv, "--compressed")
	}
	if o.Insecure {
		argv = append(argv, "-k")
	}
	if o.Proxy != "" {
		argv = append(argv, "-x", o.Proxy)
	}
	argv = append(argv, headerArgs...)

	prefix := ""
	if len(body) > 0 {
		switch {
		case !isPrintableBody(body):
			out.StdinBase64 = base64.StdEncoding.EncodeToString(body)
			argv = append(argv, "--data-binary", "@-")
			prefix = "printf '%s' " + ShellQuote(out.StdinBase64) + " | base64 --decode | "
		case body[0] == '@':
			// --data-binary would read "@…" as a file name.
			argv = append(argv, "--data-raw", string(body))
		default:
			argv = append(argv, "--data-binary", string(body))
		}
	}
	argv = append(argv, fullURL)

	quoted := make([]string, len(argv))
	for i, a := range argv {
		quoted[i] = ShellQuote(a)
	}
	out.Argv = argv
	out.Command = prefix + strings.Join(quoted, " ")
	return out, nil
}

// ShellQuote quotes s for POSIX sh: as-is when it holds only characters the
// shell never interprets, otherwise in single quotes with every embedded quote
// closed, backslash-escaped and reopened (quote, backslash, quote, quote).
// Single quotes suppress every expansion ($, `, \, !), so the result
// re-splits to exactly s.
func ShellQuote(s string) string {
	if s != "" && curlSafeArg.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// curlTarget resolves the scheme, authority (default port omitted) and
// origin-form request target from the record's URL and the request line's
// target, which may itself be absolute-form (a proxy-style request).
func curlTarget(targetURL, target string) (scheme, authority, path string, err error) {
	path = target
	var absolute *url.URL
	if lower := strings.ToLower(target); strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		if u, perr := url.Parse(target); perr == nil {
			absolute = u
		}
		rest := target[strings.Index(target, "://")+3:]
		if i := strings.IndexAny(rest, "/?"); i >= 0 {
			path = rest[i:]
		} else {
			path = "/"
		}
	}
	if path == "" || path == "*" {
		path = "/"
	} else if path[0] == '?' {
		path = "/" + path
	} else if path[0] != '/' {
		path = "/" + path
	}

	base := absolute
	if strings.TrimSpace(targetURL) != "" {
		u, perr := url.Parse(strings.TrimSpace(targetURL))
		if perr != nil || u.Host == "" {
			return "", "", "", fmt.Errorf("invalid target URL %q", targetURL)
		}
		base = u
	}
	if base == nil || base.Host == "" {
		return "", "", "", ErrCurlNoTarget
	}
	scheme = strings.ToLower(base.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", "", fmt.Errorf("unsupported scheme %q in target URL", base.Scheme)
	}
	return scheme, canonicalAuthority(scheme, base.Host), path, nil
}

// canonicalAuthority lower-cases the host and drops the scheme's default port.
func canonicalAuthority(scheme, hostport string) string {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return strings.ToLower(hostport)
	}
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		if strings.Contains(host, ":") {
			return "[" + strings.ToLower(host) + "]"
		}
		return strings.ToLower(host)
	}
	return strings.ToLower(net.JoinHostPort(host, port))
}

// sameAuthority reports whether a Host header names the URL's authority.
func sameAuthority(hostHeader, scheme, authority string) bool {
	return canonicalAuthority(scheme, strings.TrimSpace(hostHeader)) == authority
}

// needsPathAsIs reports whether curl's dot-segment squashing would change the
// path, or the path carries an encoded slash a test may depend on.
func needsPathAsIs(target string) bool {
	path, _, _ := strings.Cut(target, "?")
	if strings.Contains(strings.ToLower(path), "%2f") {
		return true
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// isPrintableBody reports whether body can be passed inline: valid UTF-8 with
// no control characters other than tab, CR and LF (NUL cannot appear in an
// argv string at all, and the rest are hazardous on a terminal).
func isPrintableBody(body []byte) bool {
	if !utf8.Valid(body) {
		return false
	}
	for _, r := range string(body) {
		if r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
