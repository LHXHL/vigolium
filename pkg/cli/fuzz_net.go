package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	gohttp "net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/vigolium/vigolium/pkg/fuzz"
	"github.com/vigolium/vigolium/pkg/input/formats/curl"
)

// Curl-compatible network options. These are spelled with curl's long names so
// a command can be transliterated flag-for-flag; the short forms are left to
// vigolium's own meanings (-u is a record UUID, -i an input, -w a wordlist),
// since silently redefining them would break every existing invocation.
var (
	fuzzCookie         string
	fuzzUser           string
	fuzzUserAgent      string
	fuzzReferer        string
	fuzzInsecure       bool
	fuzzVerifyTLS      bool
	fuzzMaxRedirs      int
	fuzzConnectTimeout time.Duration
	fuzzMaxTime        time.Duration
	fuzzHTTPVersion    string
	fuzzResolve        []string
	fuzzClientCert     string
	fuzzClientKey      string
	fuzzCACert         string

	// Body builders, sharing curl's own assembly rules.
	fuzzDataRaw       []string
	fuzzDataBinary    []string
	fuzzDataURLEncode []string
	fuzzForm          []string
	fuzzFormString    []string
	fuzzAsGet         bool
	fuzzAsHead        bool

	// Session / auth carry-over, mirroring replay.
	fuzzAuthSession string
	fuzzSessionID   string
	fuzzNoCookies   bool
)

// registerFuzzNetFlags adds the curl-compatible request and network flags.
func registerFuzzNetFlags(f *pflag.FlagSet) {
	// Request identity (become headers).
	f.StringVar(&fuzzCookie, "cookie", "", "Cookie header value, curl's -b (e.g. 'a=1; b=2')")
	f.StringVar(&fuzzUser, "user", "", "Basic auth 'user:password', curl's -u")
	f.StringVar(&fuzzUserAgent, "user-agent", "", "User-Agent header, curl's -A")
	f.StringVar(&fuzzReferer, "referer", "", "Referer header, curl's -e")

	// Body construction, same semantics as curl's.
	f.StringArrayVar(&fuzzDataRaw, "data-raw", nil, "Body data with '@' taken literally (repeatable)")
	f.StringArrayVar(&fuzzDataBinary, "data-binary", nil, "Body data; '@file' is read verbatim, newlines kept (repeatable)")
	f.StringArrayVar(&fuzzDataURLEncode, "data-urlencode", nil, "URL-encoded body data; supports curl's name=value, @file and name@file forms (repeatable)")
	f.StringArrayVar(&fuzzForm, "form", nil, "multipart/form-data field 'name=value', 'name=@file' or 'name=<file' (repeatable)")
	f.StringArrayVar(&fuzzFormString, "form-string", nil, "multipart field whose value is never interpreted (repeatable)")
	f.BoolVar(&fuzzAsGet, "get", false, "Send the accumulated data as query parameters on a GET, curl's -G")
	f.BoolVar(&fuzzAsHead, "head", false, "Use HEAD, curl's -I")

	// Transport.
	f.BoolVar(&fuzzInsecure, "insecure", false, "Skip TLS verification (already the default; accepted for curl compatibility)")
	f.BoolVar(&fuzzVerifyTLS, "verify-tls", false, "Verify TLS certificates — the inverse of --insecure, and NOT the default")
	f.IntVar(&fuzzMaxRedirs, "max-redirs", 0, "Maximum redirects to follow (0 = Go's default of 10)")
	f.DurationVar(&fuzzConnectTimeout, "connect-timeout", 0, "TCP/TLS connect timeout (e.g. 5s)")
	f.DurationVar(&fuzzMaxTime, "max-time", 0, "Total per-request budget; alias for --timeout, curl's -m")
	f.StringVar(&fuzzHTTPVersion, "http-version", "", "Force a wire protocol: 1.1 or 2 (curl's --http1.1 / --http2)")
	f.StringArrayVar(&fuzzResolve, "resolve", nil, "Pin a host to an address, curl's --resolve host:port:addr (repeatable)")
	f.StringVar(&fuzzClientCert, "cert", "", "Client certificate file (PEM), curl's -E")
	f.StringVar(&fuzzClientKey, "key", "", "Client certificate private key file (PEM)")
	f.StringVar(&fuzzCACert, "cacert", "", "CA bundle used to verify the target (implies --verify-tls)")

	// Options curl has that vigolium already does by default. They are
	// accepted so a transliterated command doesn't have to be edited, and
	// bound to a throwaway destination rather than a package var, so nobody
	// later mistakes an intentional no-op for a flag someone forgot to wire.
	for _, inert := range []struct{ name, help string }{
		{"location", "Follow 30x redirects (already the default; use --no-redirects to stop)"},
		{"compressed", "Request a compressed response (already transparent)"},
		{"path-as-is", "Send the path byte-for-byte (already the case; see pkg/replay wire fidelity)"},
	} {
		f.BoolVar(new(bool), inert.name, false, inert.help+" — accepted for curl compatibility")
	}

	// Session / auth.
	f.StringVar(&fuzzAuthSession, "auth-session", "", "Auth session name whose headers are merged in (from 'vigolium auth list')")
	f.StringVar(&fuzzSessionID, "session-id", "", "Persist cookies across runs under ~/.vigolium/replay-jars/<id>.json")
	f.BoolVar(&fuzzNoCookies, "no-cookies", false, "Don't carry cookies (overrides --session-id)")

	// curl spells the HTTP version as two boolean flags; accept those too so a
	// transliterated command doesn't need editing.
	f.BoolVar(&fuzzHTTP11, "http1.1", false, "Force HTTP/1.1")
	f.BoolVar(&fuzzHTTP2, "http2", false, "Force HTTP/2")
}

var (
	fuzzHTTP11 bool
	fuzzHTTP2  bool
)

// buildFuzzOverrides folds every request-shaping flag into one Overrides.
//
// Precedence runs lowest-to-highest: an auth session's stored headers, then
// the curl identity flags, then -H. That ordering lets an operator load a
// session and still override one of its headers for a single run, which is the
// common case when testing whether a header is what actually authorizes a
// request.
func buildFuzzOverrides(ctx context.Context, src *replaySource, fromPositionalURL bool) (fuzz.Overrides, error) {
	var o fuzz.Overrides

	if fuzzAsHead {
		o.Method = "HEAD"
	} else if fuzzMethod != "" {
		o.Method = fuzzMethod
	}

	sessionHeaders, err := fuzzAuthSessionHeaders(ctx, src)
	if err != nil {
		return o, err
	}
	o.Headers = append(o.Headers, sessionHeaders...)

	if fuzzUserAgent != "" {
		o.Headers = append(o.Headers, "User-Agent: "+fuzzUserAgent)
	}
	if fuzzReferer != "" {
		o.Headers = append(o.Headers, "Referer: "+fuzzReferer)
	}
	if fuzzCookie != "" {
		o.Headers = append(o.Headers, "Cookie: "+fuzzCookie)
	}
	if fuzzUser != "" {
		o.Headers = append(o.Headers, "Authorization: Basic "+basicAuthValue(fuzzUser))
	}

	body, contentType, err := buildFuzzBody(fromPositionalURL)
	if err != nil {
		return o, err
	}
	switch {
	case fuzzAsGet && body != "":
		// -G routes the data to the query string and leaves the body empty.
		o.QueryAppend = body
	case body != "":
		o.Body = body
		if contentType != "" {
			o.Headers = append(o.Headers, "Content-Type: "+contentType)
		}
		if o.Method == "" && !fuzzAsHead {
			o.Method = "POST"
		}
	}

	// -H last so it wins over everything synthesized above.
	o.Headers = append(o.Headers, fuzzHeaders...)
	return o, nil
}

// buildFuzzBody assembles the body from the curl data/form flags, reusing the
// curl package's own assembly so --data-urlencode and --form behave identically
// whether they arrive as `fuzz` flags or inside a pasted curl command.
//
// -d is skipped when the request came from a positional URL, because
// buildRequestFromFlags already folded it in there.
func buildFuzzBody(fromPositionalURL bool) (body, contentType string, err error) {
	var parts []string

	if fuzzData != "" && !fromPositionalURL {
		v, derr := curl.ResolveData(fuzzData, curl.DataAscii)
		if derr != nil {
			return "", "", derr
		}
		parts = append(parts, v)
	}
	for _, spec := range []struct {
		values []string
		kind   curl.DataKind
	}{
		{fuzzDataRaw, curl.DataRaw},
		{fuzzDataBinary, curl.DataBinary},
		{fuzzDataURLEncode, curl.DataURLEncode},
	} {
		for _, v := range spec.values {
			resolved, derr := curl.ResolveData(v, spec.kind)
			if derr != nil {
				return "", "", derr
			}
			parts = append(parts, resolved)
		}
	}

	if len(fuzzForm) > 0 || len(fuzzFormString) > 0 {
		if len(parts) > 0 {
			return "", "", usageErrorf("--form cannot be combined with the --data flags (curl builds one body, not both)")
		}
		body, contentType = curl.BuildMultipartBody(fuzzForm, fuzzFormString)
		return body, contentType, nil
	}

	if len(parts) == 0 {
		return "", "", nil
	}
	body = strings.Join(parts, "&")
	return body, curl.GuessContentType(body), nil
}

// fuzzAuthSessionHeaders resolves --auth-session into header overrides for the
// request's host.
func fuzzAuthSessionHeaders(ctx context.Context, src *replaySource) ([]string, error) {
	if fuzzAuthSession == "" {
		return nil, nil
	}
	overlay, err := resolveAuthSessionHeaders(ctx, fuzzAuthSession, src.Hostname)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(overlay))
	for name := range overlay {
		names = append(names, name)
	}
	sort.Strings(names) // deterministic order so runs are reproducible
	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, name+": "+overlay[name])
	}
	return out, nil
}

// resolveFuzzTimeout reconciles --timeout with curl's --max-time; the smaller
// non-zero value wins so neither can silently extend the other.
func resolveFuzzTimeout() time.Duration {
	switch {
	case fuzzMaxTime > 0 && fuzzTimeout > 0:
		if fuzzMaxTime < fuzzTimeout {
			return fuzzMaxTime
		}
		return fuzzTimeout
	case fuzzMaxTime > 0:
		return fuzzMaxTime
	default:
		return fuzzTimeout
	}
}

// fuzzHTTPVersionSetting folds curl's --http1.1/--http2 booleans and the
// explicit --http-version into one value.
func fuzzHTTPVersionSetting() (string, error) {
	if fuzzHTTP11 && fuzzHTTP2 {
		return "", usageErrorf("--http1.1 and --http2 are mutually exclusive")
	}
	switch {
	case fuzzHTTP11:
		return "1.1", nil
	case fuzzHTTP2:
		return "2", nil
	}
	switch v := strings.TrimSpace(fuzzHTTPVersion); v {
	case "", "1.1", "2":
		return v, nil
	case "1", "http1.1":
		return "1.1", nil
	case "http2", "2.0":
		return "2", nil
	default:
		return "", usageErrorf("--http-version %q: want 1.1 or 2", v)
	}
}

// buildFuzzClient constructs the HTTP client for a fuzz run from the
// curl-compatible transport flags, starting from replay's client (which
// carries the --proxy routing and the permissive TLS default) and layering the
// explicit options on top.
func buildFuzzClient(cookies gohttp.CookieJar) (*gohttp.Client, error) {
	client := newReplayClient(nil, resolveFuzzTimeout())
	client.Jar = cookies

	transport, ok := client.Transport.(*gohttp.Transport)
	if !ok {
		return client, nil
	}
	transport = transport.Clone()

	tlsCfg := transport.TLSClientConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{} //nolint:gosec // verification is configured just below
	}

	// Verification is off by default (staging and self-signed targets are the
	// norm); --verify-tls and --cacert are the ways to turn it on.
	tlsCfg.InsecureSkipVerify = !fuzzVerifyTLS && fuzzCACert == "" //nolint:gosec // deliberate default for a scanner

	if fuzzCACert != "" {
		pem, err := os.ReadFile(fuzzCACert)
		if err != nil {
			return nil, fmt.Errorf("read --cacert %q: %w", fuzzCACert, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			//vigolium:not-usage decided from file contents, after I/O
			return nil, fmt.Errorf("--cacert %q: no certificates found", fuzzCACert)
		}
		tlsCfg.RootCAs = pool
	}

	if fuzzClientCert != "" {
		keyFile := fuzzClientKey
		if keyFile == "" {
			// curl allows the key to live in the same PEM as the cert.
			keyFile = fuzzClientCert
		}
		cert, err := tls.LoadX509KeyPair(fuzzClientCert, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load --cert/--key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	} else if fuzzClientKey != "" {
		return nil, usageErrorf("--key requires --cert")
	}
	transport.TLSClientConfig = tlsCfg

	version, err := fuzzHTTPVersionSetting()
	if err != nil {
		return nil, err
	}
	switch version {
	case "1.1":
		// An empty non-nil TLSNextProto map is Go's documented way to disable
		// the automatic HTTP/2 upgrade.
		transport.ForceAttemptHTTP2 = false
		transport.TLSNextProto = map[string]func(string, *tls.Conn) gohttp.RoundTripper{}
	case "2":
		transport.ForceAttemptHTTP2 = true
	}

	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	if fuzzConnectTimeout > 0 {
		dialer.Timeout = fuzzConnectTimeout
	}
	overrides, err := parseResolveOverrides(fuzzResolve)
	if err != nil {
		return nil, err
	}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if target, ok := overrides[strings.ToLower(addr)]; ok {
			addr = target
		}
		return dialer.DialContext(ctx, network, addr)
	}

	// Go's default MaxIdleConnsPerHost is 2. A fuzzer points all of its
	// concurrency at ONE host, so at -c 10 eight of every ten connections were
	// closed instead of pooled and the next send paid a fresh TCP+TLS
	// handshake — several RTTs on the large majority of requests.
	if fuzzConcurrency > transport.MaxIdleConnsPerHost {
		transport.MaxIdleConnsPerHost = fuzzConcurrency
		transport.MaxIdleConns = fuzzConcurrency * 2
	}
	client.Transport = transport

	if fuzzMaxRedirs > 0 {
		limit := fuzzMaxRedirs
		client.CheckRedirect = func(_ *gohttp.Request, via []*gohttp.Request) error {
			if len(via) >= limit {
				return fmt.Errorf("stopped after %d redirects", limit)
			}
			return nil
		}
	}
	return client, nil
}

// parseResolveOverrides turns curl's "host:port:addr" entries into an
// addr→addr dial map. curl also accepts a leading "+" (meaning the entry
// expires) and "*" as a wildcard host; the "+" is accepted and ignored.
func parseResolveOverrides(entries []string) (map[string]string, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(entries))
	for _, e := range entries {
		spec := strings.TrimPrefix(strings.TrimSpace(e), "+")
		parts := strings.Split(spec, ":")
		if len(parts) < 3 {
			return nil, usageErrorf("--resolve %q: want host:port:address", e)
		}
		host, port := parts[0], parts[1]
		addr := strings.Join(parts[2:], ":") // IPv6 literals carry colons
		addr = strings.Trim(addr, "[]")
		if host == "" || port == "" || addr == "" {
			return nil, usageErrorf("--resolve %q: want host:port:address", e)
		}
		out[strings.ToLower(net.JoinHostPort(host, port))] = net.JoinHostPort(addr, port)
	}
	return out, nil
}

// fuzzCookieJar opens the persistent jar for --session-id, returning a nil jar
// (and a no-op save) when cookies aren't being carried. Cookies matter here
// because a fuzz run is hundreds of requests against a session that a single
// rotation would otherwise invalidate halfway through.
func fuzzCookieJar() (gohttp.CookieJar, int, func(), error) {
	if fuzzNoCookies || fuzzSessionID == "" {
		return nil, 0, func() {}, nil
	}
	pj, loaded, err := openSessionJar(fuzzSessionID)
	if err != nil {
		return nil, 0, func() {}, err
	}
	return pj, loaded, func() { saveReplayJar(pj) }, nil
}

// validateFuzzNetFlags rejects contradictory transport options up front, so a
// long run doesn't start before an unusable combination is noticed.
func validateFuzzNetFlags() error {
	if fuzzVerifyTLS && fuzzInsecure {
		return usageErrorf("--insecure and --verify-tls are mutually exclusive")
	}
	if _, err := fuzzHTTPVersionSetting(); err != nil {
		return err
	}
	if _, err := parseResolveOverrides(fuzzResolve); err != nil {
		return err
	}
	if fuzzAsGet && fuzzAsHead {
		return usageErrorf("--get and --head are mutually exclusive")
	}
	return nil
}

// basicAuthValue encodes a curl-style "user:password" for an Authorization
// header.
func basicAuthValue(userPass string) string {
	return base64.StdEncoding.EncodeToString([]byte(userPass))
}
