package curl

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

type header struct {
	key   string
	value string
}

// dataPart is one accumulated body-data flag, kept unresolved until assembly
// so -G can route it to the query string instead.
type dataPart struct {
	value string
	kind  DataKind
}

// curlSpec accumulates everything a curl command says about the request while
// the flags are scanned; assembly happens once, in build.
type curlSpec struct {
	method         string
	methodExplicit bool

	rawURL string

	headers     []header
	data        []dataPart
	forms       []string
	formStrings []string
	cookies     []string

	basicAuth string
	bearer    string
	userAgent string
	referer   string

	asGet         bool // -G: send data as query params
	asHead        bool // -I: HEAD
	uploadFile    string
	jsonShorthand bool // --json: implies JSON content-type and Accept

	hints TransportHints
}

func (s *curlSpec) setMethod(v string) {
	s.method = strings.ToUpper(strings.TrimSpace(v))
	s.methodExplicit = true
}

func (s *curlSpec) addHeader(v string) error {
	// curl's "Name;" form sends an empty header; "Name:" removes a default.
	if k, val, ok := parseHeader(v); ok {
		s.headers = append(s.headers, header{key: k, value: val})
		return nil
	}
	if name, ok := strings.CutSuffix(strings.TrimSpace(v), ";"); ok {
		s.headers = append(s.headers, header{key: strings.TrimSpace(name), value: ""})
		return nil
	}
	return fmt.Errorf("bad -H value %q: want 'Name: value'", v)
}

func (s *curlSpec) addData(v string, kind DataKind) {
	s.data = append(s.data, dataPart{value: v, kind: kind})
}

func (s *curlSpec) addCookie(v string) {
	// curl treats a -b value containing '=' as inline cookies and anything
	// else as a cookie-jar file path to load from.
	if strings.Contains(v, "=") {
		s.cookies = append(s.cookies, v)
	}
}

func (s *curlSpec) setURL(v, source string) error {
	if s.rawURL != "" {
		return fmt.Errorf("multiple URLs in one curl command (%q and %q via %s); split them into separate commands", s.rawURL, v, source)
	}
	s.rawURL = v
	return nil
}

// ParseSingleCommand parses a single curl command string into an
// HttpRequestResponse, discarding any transport-only options.
func ParseSingleCommand(cmd string) (*httpmsg.HttpRequestResponse, error) {
	rr, _, err := ParseSingleCommandWithHints(cmd)
	return rr, err
}

// ParseSingleCommandWithHints parses a curl command and additionally returns
// the transport options it carried (proxy, timeouts, TLS material, HTTP
// version, ...), which don't fit in the request bytes but change how a caller
// should send them.
//
// Unknown flags are rejected rather than skipped — see curlFlag for why.
func ParseSingleCommandWithHints(cmd string) (*httpmsg.HttpRequestResponse, TransportHints, error) {
	var spec curlSpec

	tokens, err := tokenizeCurlCommand(cmd)
	if err != nil {
		return nil, spec.hints, err
	}
	if len(tokens) == 0 {
		return nil, spec.hints, fmt.Errorf("empty curl command")
	}

	// Skip a leading "curl" (possibly path-qualified, possibly a shell prompt).
	start := 0
	for start < len(tokens) && isCurlToken(tokens[start]) {
		start++
	}

	endOfFlags := false
	for i := start; i < len(tokens); i++ {
		tok := tokens[i]

		switch {
		case endOfFlags || tok == "-" || !strings.HasPrefix(tok, "-"):
			if err := spec.setURL(tok, "positional argument"); err != nil {
				return nil, spec.hints, err
			}

		case tok == "--":
			endOfFlags = true

		case strings.HasPrefix(tok, "--"):
			consumed, err := applyLongFlag(&spec, tok, tokens, i)
			if err != nil {
				return nil, spec.hints, err
			}
			i += consumed

		default:
			consumed, err := applyShortCluster(&spec, tok, tokens, i)
			if err != nil {
				return nil, spec.hints, err
			}
			i += consumed
		}
	}

	return spec.build()
}

// isCurlToken reports whether tok is the command word itself rather than an
// argument — "curl", "/usr/bin/curl", "curl.exe", or a copied "$"/"#" prompt.
func isCurlToken(tok string) bool {
	if tok == "$" || tok == "#" {
		return true
	}
	base := tok
	if i := strings.LastIndexAny(tok, `/\`); i >= 0 {
		base = tok[i+1:]
	}
	return base == "curl" || base == "curl.exe"
}

// applyLongFlag handles one "--name" (or "--name=value") token, returning how
// many extra tokens it consumed.
func applyLongFlag(spec *curlSpec, tok string, tokens []string, i int) (int, error) {
	name := strings.TrimPrefix(tok, "--")
	value, attached := "", false
	if n, v, ok := strings.Cut(name, "="); ok {
		name, value, attached = n, v, true
	}

	flag, ok := longFlags[name]
	if !ok {
		// curl accepts --no-<flag> for any boolean option. Negating something
		// we track is a no-op for request reconstruction — only the
		// affirmative form carries meaning.
		if base, negated := strings.CutPrefix(name, "no-"); negated {
			if bf, known := longFlags[base]; known && !bf.arg {
				return 0, nil
			}
		}
		return 0, unknownFlagError(tok)
	}

	consumed := 0
	if flag.arg && !attached {
		if i+1 >= len(tokens) {
			return 0, fmt.Errorf("curl flag %s expects a value", tok)
		}
		value = tokens[i+1]
		consumed = 1
	}
	if !flag.arg && attached {
		return 0, fmt.Errorf("curl flag %s does not take a value", tok)
	}
	if flag.apply != nil {
		if err := flag.apply(spec, value); err != nil {
			return 0, err
		}
	}
	return consumed, nil
}

// applyShortCluster handles a short-option token, which may cluster several
// flags ("-sSL") and may carry an arg-taking flag's value attached ("-XPOST",
// "-H'A: b'" once the tokenizer has stripped the quotes).
func applyShortCluster(spec *curlSpec, tok string, tokens []string, i int) (int, error) {
	body := tok[1:]

	for pos := 0; pos < len(body); pos++ {
		ch := body[pos]
		flag, ok := shortFlags[ch]
		if !ok {
			return 0, unknownFlagError("-" + string(ch))
		}

		if !flag.arg {
			if flag.apply != nil {
				if err := flag.apply(spec, ""); err != nil {
					return 0, err
				}
			}
			continue
		}

		// Arg-taking: the rest of this token is the value if there is one,
		// otherwise the next token. Either way this flag ends the cluster.
		value, consumed := body[pos+1:], 0
		if value == "" {
			if i+1 >= len(tokens) {
				return 0, fmt.Errorf("curl flag -%c expects a value", ch)
			}
			value, consumed = tokens[i+1], 1
		}
		if flag.apply != nil {
			if err := flag.apply(spec, value); err != nil {
				return 0, err
			}
		}
		return consumed, nil
	}
	return 0, nil
}

// unknownFlagError explains why an unrecognized flag is fatal rather than
// skipped, since "curl worked, vigolium didn't" needs a reason.
func unknownFlagError(flag string) error {
	return fmt.Errorf("unrecognized curl flag %q: refusing to guess whether it takes a value, "+
		"because skipping it would make its argument look like the target URL "+
		"(remove the flag, or report it so it can be added)", flag)
}

// build assembles the accumulated spec into a request.
func (s *curlSpec) build() (*httpmsg.HttpRequestResponse, TransportHints, error) {
	if s.rawURL == "" {
		return nil, s.hints, fmt.Errorf("no URL found in curl command")
	}

	// Resolve every data flag now; -G decides where the result lands.
	var dataValues []string
	for _, d := range s.data {
		v, err := ResolveData(d.value, d.kind)
		if err != nil {
			return nil, s.hints, err
		}
		dataValues = append(dataValues, v)
	}
	dataJoined := strings.Join(dataValues, "&")

	var (
		body        string
		contentType string
	)

	switch {
	case len(s.forms) > 0 || len(s.formStrings) > 0:
		body, contentType = BuildMultipartBody(s.forms, s.formStrings)

	case s.uploadFile != "":
		content, err := readDataFile(s.uploadFile)
		if err != nil {
			return nil, s.hints, err
		}
		body = content
		contentType = "application/octet-stream"

	case s.asGet:
		// -G moves the data into the query string; the body stays empty.
		if dataJoined != "" {
			merged, err := appendQuery(s.rawURL, dataJoined)
			if err != nil {
				return nil, s.hints, err
			}
			s.rawURL = merged
		}

	case dataJoined != "":
		body = dataJoined
		if s.jsonShorthand {
			contentType = "application/json"
		} else {
			contentType = GuessContentType(body)
		}
	}

	method := s.resolveMethod(body)

	headers := s.assembleHeaders(contentType)

	rr, err := buildRawHTTPRequest(method, s.rawURL, headers, body)
	return rr, s.hints, err
}

// resolveMethod applies curl's implicit-verb rules: -X wins, then -I means
// HEAD, then a body (or -T) means POST/PUT, else GET.
func (s *curlSpec) resolveMethod(body string) string {
	switch {
	case s.methodExplicit && s.method != "":
		return s.method
	case s.asHead:
		return "HEAD"
	case s.uploadFile != "":
		return "PUT"
	case body != "" && !s.asGet:
		return "POST"
	default:
		return "GET"
	}
}

// assembleHeaders merges the explicit -H headers with the ones curl would
// synthesize from -b/-u/-A/-e/--json. Explicit headers always win.
func (s *curlSpec) assembleHeaders(contentType string) []header {
	headers := append([]header(nil), s.headers...)

	add := func(k, v string) {
		if v != "" && !hasHeader(headers, k) {
			headers = append(headers, header{key: k, value: v})
		}
	}

	if len(s.cookies) > 0 && !hasHeader(headers, "Cookie") {
		headers = append(headers, header{key: "Cookie", value: strings.Join(s.cookies, "; ")})
	}
	if s.basicAuth != "" {
		add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(s.basicAuth)))
	}
	if s.bearer != "" {
		add("Authorization", "Bearer "+s.bearer)
	}
	add("User-Agent", s.userAgent)
	add("Referer", s.referer)
	if s.jsonShorthand {
		add("Accept", "application/json")
	}
	add("Content-Type", contentType)

	return headers
}

// appendQuery merges -G data into the URL's query string.
func appendQuery(rawURL, query string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL %q: %w", rawURL, err)
	}
	if u.RawQuery == "" {
		u.RawQuery = query
	} else {
		u.RawQuery += "&" + query
	}
	return u.String(), nil
}

// tokenizeCurlCommand splits a curl command string into tokens the way a POSIX
// shell would for a simple command: single quotes, double quotes, backslash
// escapes, backslash-newline continuations, and bash's ANSI-C `$'...'` quoting
// (what Chrome's "Copy as cURL (bash)" emits for any body containing a quote,
// newline or non-ASCII byte). `$"..."` is treated as a plain double-quoted
// string. An unterminated quote is an error: guessing where it should have
// ended would silently produce a different request body.
func tokenizeCurlCommand(cmd string) ([]string, error) {
	var tokens []string
	var current strings.Builder
	inSingle := false
	inDouble := false
	escaped := false
	quoted := false

	for i := 0; i < len(cmd); i++ {
		ch := cmd[i]

		if escaped {
			// In double quotes, only certain chars are special after backslash
			if inDouble && ch != '"' && ch != '\\' && ch != '$' && ch != '`' {
				current.WriteByte('\\')
			}
			current.WriteByte(ch)
			escaped = false
			continue
		}

		switch {
		case ch == '\\' && !inSingle:
			// Check if this is a line continuation (backslash at end of line)
			if i+1 < len(cmd) && (cmd[i+1] == '\n' || cmd[i+1] == '\r') {
				// Skip the backslash and newline (line continuation)
				i++
				if i+1 < len(cmd) && cmd[i] == '\r' && cmd[i+1] == '\n' {
					i++ // skip \r\n
				}
				continue
			}
			escaped = true

		case ch == '$' && !inSingle && !inDouble && i+1 < len(cmd) && cmd[i+1] == '\'':
			// ANSI-C quoting: $'...'
			decoded, next, err := decodeANSICQuoted(cmd, i+2)
			if err != nil {
				return nil, err
			}
			current.WriteString(decoded)
			quoted = true
			i = next

		case ch == '$' && !inSingle && !inDouble && i+1 < len(cmd) && cmd[i+1] == '"':
			// Locale-translated string $"..." — no translation, plain double quotes.
			inDouble = true
			quoted = true
			i++

		case ch == '\'' && !inDouble:
			inSingle = !inSingle
			quoted = true

		case ch == '"' && !inSingle:
			inDouble = !inDouble
			quoted = true

		case (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r') && !inSingle && !inDouble:
			if current.Len() > 0 || quoted {
				tokens = append(tokens, current.String())
				current.Reset()
				quoted = false
			}

		default:
			current.WriteByte(ch)
		}
	}

	switch {
	case inSingle:
		return nil, fmt.Errorf("unterminated single quote in curl command")
	case inDouble:
		return nil, fmt.Errorf("unterminated double quote in curl command")
	case escaped:
		// A lone trailing backslash: the shell would wait for more input.
		return nil, fmt.Errorf("curl command ends with a dangling backslash")
	}

	if current.Len() > 0 || quoted {
		tokens = append(tokens, current.String())
	}

	return tokens, nil
}

// decodeANSICQuoted decodes the body of a bash `$'...'` string starting at
// cmd[start] (just past the opening quote). It returns the decoded text and
// the index of the closing quote.
//
// Supported escapes follow bash: \a \b \e \E \f \n \r \t \v \\ \' \" \?
// \NNN (1-3 octal digits), \xHH (1-2 hex digits), \uHHHH and \UHHHHHHHH
// (encoded as UTF-8), and \cX (control character). Any other escaped byte is
// kept with its backslash, as bash does.
func decodeANSICQuoted(cmd string, start int) (string, int, error) {
	var sb strings.Builder
	for i := start; i < len(cmd); i++ {
		ch := cmd[i]
		if ch == '\'' {
			return sb.String(), i, nil
		}
		if ch != '\\' {
			sb.WriteByte(ch)
			continue
		}
		if i+1 >= len(cmd) {
			break
		}
		i++
		switch e := cmd[i]; e {
		case 'a':
			sb.WriteByte('\a')
		case 'b':
			sb.WriteByte('\b')
		case 'e', 'E':
			sb.WriteByte(0x1b)
		case 'f':
			sb.WriteByte('\f')
		case 'n':
			sb.WriteByte('\n')
		case 'r':
			sb.WriteByte('\r')
		case 't':
			sb.WriteByte('\t')
		case 'v':
			sb.WriteByte('\v')
		case '\\', '\'', '"', '?':
			sb.WriteByte(e)
		case 'x':
			n, consumed := parseRadix(cmd[i+1:], 16, 2)
			if consumed == 0 {
				sb.WriteString(`\x`)
				continue
			}
			sb.WriteByte(byte(n))
			i += consumed
		case 'u', 'U':
			width := 4
			if e == 'U' {
				width = 8
			}
			n, consumed := parseRadix(cmd[i+1:], 16, width)
			if consumed == 0 {
				sb.WriteByte('\\')
				sb.WriteByte(e)
				continue
			}
			sb.WriteRune(rune(n))
			i += consumed
		case 'c':
			if i+1 < len(cmd) {
				i++
				sb.WriteByte(cmd[i] & 0x1f)
			}
		case '0', '1', '2', '3', '4', '5', '6', '7':
			n, consumed := parseRadix(cmd[i:], 8, 3)
			sb.WriteByte(byte(n))
			i += consumed - 1
		default:
			sb.WriteByte('\\')
			sb.WriteByte(e)
		}
	}
	return "", 0, fmt.Errorf("unterminated $'...' quote in curl command")
}

// parseRadix reads up to maxDigits digits of the given base from the front of
// s, returning the value and how many bytes it consumed.
func parseRadix(s string, base, maxDigits int) (int, int) {
	n, i := 0, 0
	for ; i < len(s) && i < maxDigits; i++ {
		d := digitValue(s[i])
		if d < 0 || d >= base {
			break
		}
		n = n*base + d
	}
	return n, i
}

func digitValue(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	default:
		return -1
	}
}

// buildRawHTTPRequest assembles a raw HTTP request string and calls httpmsg.ParseRawRequestWithURL.
func buildRawHTTPRequest(method, fullURL string, headers []header, body string) (*httpmsg.HttpRequestResponse, error) {
	parsedURL, err := url.Parse(fullURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", fullURL, err)
	}

	path := parsedURL.RequestURI()
	host := parsedURL.Host

	var headerLines []string
	headerLines = append(headerLines, fmt.Sprintf("Host: %s", host))

	for _, h := range headers {
		headerLines = append(headerLines, fmt.Sprintf("%s: %s", h.key, h.value))
	}

	// Add Content-Length for requests with body
	if body != "" {
		headerLines = append(headerLines, fmt.Sprintf("Content-Length: %d", len(body)))
	}

	// Assemble raw HTTP request
	var raw strings.Builder
	fmt.Fprintf(&raw, "%s %s HTTP/1.1\r\n", method, path)
	for _, h := range headerLines {
		raw.WriteString(h)
		raw.WriteString("\r\n")
	}
	raw.WriteString("\r\n")
	if body != "" {
		raw.WriteString(body)
	}

	return httpmsg.ParseRawRequestWithURL(raw.String(), fullURL)
}

// parseHeader splits a "Key: Value" string into key and value.
func parseHeader(s string) (string, string, bool) {
	key, value, ok := strings.Cut(s, ":")
	if !ok {
		return "", "", false
	}
	return strings.TrimSpace(key), strings.TrimSpace(value), true
}

// hasHeader checks if a header with the given name exists (case-insensitive).
func hasHeader(headers []header, name string) bool {
	for _, h := range headers {
		if strings.EqualFold(h.key, name) {
			return true
		}
	}
	return false
}
