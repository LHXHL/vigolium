package http_request_smuggling

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	nethttp "net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/tlsprobe"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// CL.0 desync
//
// A back-end that ignores Content-Length on some endpoints (static files,
// redirects, /favicon.ico are the usual suspects) treats a POST's body as the
// start of the NEXT request on the connection. The probe is a POST whose
// correctly declared body is a smuggled request prefix:
//
//	POST /favicon.ico HTTP/1.1          GET /<canary> HTTP/1.1
//	Content-Length: N             ==>   X-Ignore: xGET /favicon.ico HTTP/1.1
//	                                    Host: ...
//	GET /<canary> HTTP/1.1
//	X-Ignore: x
//
// The follow-up GET on the same connection is glued onto the prefix, so a
// vulnerable back-end answers it with the canary's 404 instead of its own
// response. Unlike the CL/TE probes this is an observed effect on a second
// request, not a timing inference.
//
// Connection reuse is the whole primitive, and the shared Requester cannot give
// it: rawhttp closes the socket after every response. The pairs therefore go
// over a connection this file dials itself, and a pair only counts when the
// follow-up was answered on that same reused connection.

// cl0IOTimeout bounds one whole exchange (dial, every write and read). A var
// only so tests can shrink it; see the note on the timing thresholds.
var cl0IOTimeout = 10 * time.Second

const (
	// cl0MaxBody caps how much of one response body is read. The body must be
	// consumed in full to keep the stream aligned for the next response, so a
	// larger body ends the exchange rather than being skipped.
	cl0MaxBody = 1 << 20
	// cl0EvidenceBody caps how much of a body is kept for the finding.
	cl0EvidenceBody = 4096
	// cl0MaxCandidates bounds how many paths are tried per host.
	cl0MaxCandidates = 3
	// cl0CanaryStatus is what the smuggled request is expected to earn.
	cl0CanaryStatus = 404
)

// cl0FixedCandidates are endpoints commonly served by a component that never
// reads a request body (a static-file handler, the web server itself).
var cl0FixedCandidates = []string{"/favicon.ico", "/robots.txt"}

var (
	errCL0ConnClosing = errors.New("server signalled connection close before the follow-up")
	errCL0BodyTooLong = errors.New("response body exceeds the read cap")
)

// wireResponse is one response read off a reused connection.
type wireResponse struct {
	status int
	closes bool
	raw    string // status line, headers and a truncated body, for evidence
	body   string
}

// cl0Baseline is what a candidate path answers when nothing is smuggled.
type cl0Baseline struct {
	path   string
	own    wireResponse // the follow-up's own answer
	canary wireResponse // a random path's answer
}

// cl0Attempt is one attack pair: the POST carrying the smuggled prefix and the
// follow-up that rode the same connection.
type cl0Attempt struct {
	canary   string
	request  string // both requests, in wire order
	followUp wireResponse
}

// scanCL0 runs CL.0 detection against a small set of candidate paths and
// returns at most one finding per host: the first candidate that confirms.
func scanCL0(ctx *httpmsg.HttpRequestResponse) []*output.ResultEvent {
	svc := ctx.Service()
	if svc == nil {
		return nil
	}
	for _, path := range cl0Candidates(ctx) {
		if ev := probeCL0Path(ctx, svc, path); ev != nil {
			return []*output.ResultEvent{ev}
		}
	}
	return nil
}

// cl0Candidates picks the paths to test: the captured path when it looks like a
// static asset or the capture was a redirect, then the fixed list.
func cl0Candidates(ctx *httpmsg.HttpRequestResponse) []string {
	var out []string
	add := func(p string) {
		if p == "" || len(out) >= cl0MaxCandidates {
			return
		}
		for _, have := range out {
			if have == p {
				return
			}
		}
		out = append(out, p)
	}

	if req := ctx.Request(); req != nil {
		p := req.Path()
		bare, _, _ := strings.Cut(p, "?")
		redirect := false
		if resp := ctx.Response(); resp != nil {
			code := resp.StatusCode()
			redirect = code >= 300 && code < 400
		}
		if strings.HasPrefix(p, "/") && (modkit.HasStaticAssetExtension(bare) || redirect) {
			add(p)
		}
	}
	for _, p := range cl0FixedCandidates {
		add(p)
	}
	return out
}

// probeCL0Path tests one path. Every step must pass; each failure returns nil.
//
//  1. Baseline on one reused connection: GET path, GET /<canary>, GET path. The
//     path's own answer must be stable and not the canary's 404, and the canary
//     must 404, otherwise "the follow-up got the canary's answer" is not a
//     distinguishable event. It also proves the host keeps connections alive.
//  2. Attack pair: the follow-up must come back as the canary's 404.
//  3. Control pair: a POST of the same length whose body is NOT a request
//     prefix. Its follow-up must not 404, so the 404 is attributable to the
//     smuggled request line rather than to "any POST here breaks the next GET".
//  4. Second attack pair with a fresh canary: must reproduce.
func probeCL0Path(ctx *httpmsg.HttpRequestResponse, svc *httpmsg.Service, path string) *output.ResultEvent {
	base, ok := cl0MeasureBaseline(ctx, svc, path)
	if !ok {
		return nil
	}

	first, ok := cl0Attack(ctx, svc, path, base)
	if !ok {
		return nil
	}

	control, ok := cl0Control(ctx, svc, path, len(cl0SmuggledPrefix(first.canary)))
	if !ok || control.followUp.status == cl0CanaryStatus {
		return nil
	}

	second, ok := cl0Attack(ctx, svc, path, base)
	if !ok {
		return nil
	}

	return buildCL0Result(svc, base, first, second, control)
}

func cl0MeasureBaseline(ctx *httpmsg.HttpRequestResponse, svc *httpmsg.Service, path string) (cl0Baseline, bool) {
	get, ok := buildCL0Request(ctx, "GET", path, "")
	if !ok {
		return cl0Baseline{}, false
	}
	canaryReq, ok := buildCL0Request(ctx, "GET", newCL0Canary(), "")
	if !ok {
		return cl0Baseline{}, false
	}
	resps, err := cl0Exchange(svc, [][]byte{get, canaryReq, get}, []string{"GET", "GET", "GET"})
	if err != nil {
		return cl0Baseline{}, false
	}
	own, canary, again := resps[0], resps[1], resps[2]
	if own.status != again.status || own.status == cl0CanaryStatus || canary.status != cl0CanaryStatus {
		return cl0Baseline{}, false
	}
	return cl0Baseline{path: path, own: own, canary: canary}, true
}

// cl0Attack sends one attack pair and reports whether the follow-up came back
// as the canary's answer instead of its own.
func cl0Attack(ctx *httpmsg.HttpRequestResponse, svc *httpmsg.Service, path string, base cl0Baseline) (cl0Attempt, bool) {
	canary := newCL0Canary()
	att, ok := cl0Pair(ctx, svc, path, cl0SmuggledPrefix(canary))
	if !ok {
		return att, false
	}
	att.canary = canary
	return att, att.followUp.status == cl0CanaryStatus && att.followUp.status != base.own.status
}

// cl0Control sends the benign twin of an attack pair: same method, path and
// body length, but a body that is not a request line.
func cl0Control(ctx *httpmsg.HttpRequestResponse, svc *httpmsg.Service, path string, bodyLen int) (cl0Attempt, bool) {
	if bodyLen < 2 {
		bodyLen = 2
	}
	return cl0Pair(ctx, svc, path, "x="+strings.Repeat("a", bodyLen-2))
}

// cl0Pair sends POST path (with body, correctly declared) and then GET path on
// the same connection, returning the follow-up's response.
func cl0Pair(ctx *httpmsg.HttpRequestResponse, svc *httpmsg.Service, path, body string) (cl0Attempt, bool) {
	post, ok := buildCL0Request(ctx, "POST", path, body)
	if !ok {
		return cl0Attempt{}, false
	}
	get, ok := buildCL0Request(ctx, "GET", path, "")
	if !ok {
		return cl0Attempt{}, false
	}
	att := cl0Attempt{request: string(post) + string(get)}
	resps, err := cl0Exchange(svc, [][]byte{post, get}, []string{"POST", "GET"})
	if err != nil {
		// Includes the server closing after the POST: with no reused
		// connection there is no follow-up to read, and nothing to conclude.
		return att, false
	}
	att.followUp = resps[1]
	return att, true
}

// cl0SmuggledPrefix is the attack body: a request line and an unterminated
// header that swallows the follow-up's own request line.
func cl0SmuggledPrefix(canary string) string {
	return "GET " + canary + " HTTP/1.1\r\nX-Ignore: x"
}

func newCL0Canary() string {
	return "/vgcl0" + utils.RandomString(12)
}

// cl0DropHeaders are captured headers the probe owns or that would change how
// the connection or the body behaves.
var cl0DropHeaders = map[string]bool{
	"content-length":    true,
	"transfer-encoding": true,
	"content-type":      true,
	"connection":        true,
	"keep-alive":        true,
	"proxy-connection":  true,
	"upgrade":           true,
	"expect":            true,
	"te":                true,
	"accept-encoding":   true, // keep bodies readable for canary reflection
}

// buildCL0Request renders a request for path on the captured host, keeping the
// capture's headers (Host, cookies, user agent) but owning the request line,
// connection handling and framing. The Content-Length is always correct: CL.0
// is about a back-end that ignores a truthful one.
func buildCL0Request(ctx *httpmsg.HttpRequestResponse, method, path, body string) ([]byte, bool) {
	if ctx == nil || ctx.Request() == nil {
		return nil, false
	}
	headers, _, _, err := httpmsg.ExtractAllHeaders(ctx.Request().Raw())
	if err != nil || len(headers) == 0 {
		return nil, false
	}
	lines := make([]string, 0, len(headers)+3)
	lines = append(lines, method+" "+path+" HTTP/1.1")
	for _, header := range headers[1:] {
		name, _, found := strings.Cut(header, ":")
		if !found || cl0DropHeaders[strings.ToLower(strings.TrimSpace(name))] {
			continue
		}
		lines = append(lines, header)
	}
	lines = append(lines, "Connection: keep-alive")
	if method == "POST" {
		lines = append(lines,
			"Content-Type: application/x-www-form-urlencoded",
			"Content-Length: "+strconv.Itoa(len(body)))
	}
	return httpmsg.BuildHttpMessage(lines, []byte(body)), true
}

// cl0Exchange writes each request to ONE connection in turn, reading its
// response in full before sending the next. It fails when the connection cannot
// be reused for the next request: a response that announces close, a read that
// hits EOF, or a body too large to consume.
func cl0Exchange(svc *httpmsg.Service, reqs [][]byte, methods []string) ([]wireResponse, error) {
	conn, err := cl0Dial(svc)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(cl0IOTimeout))

	br := bufio.NewReader(conn)
	out := make([]wireResponse, 0, len(reqs))
	for i, raw := range reqs {
		if _, err := conn.Write(raw); err != nil {
			return out, err
		}
		resp, err := readWireResponse(br, methods[i])
		if err != nil {
			return out, err
		}
		out = append(out, resp)
		if resp.closes && i < len(reqs)-1 {
			return out, errCL0ConnClosing
		}
	}
	return out, nil
}

func cl0Dial(svc *httpmsg.Service) (net.Conn, error) {
	addr := net.JoinHostPort(svc.Host(), strconv.Itoa(svc.Port()))
	nd := &net.Dialer{Timeout: cl0IOTimeout}
	if svc.Protocol() != "https" {
		return nd.Dial("tcp", addr)
	}
	d := &tls.Dialer{
		NetDialer: nd,
		Config: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // scanner: targets routinely use self-signed certs
			MinVersion:         tls.VersionTLS10,
			ServerName:         tlsprobe.SNIName(svc.Host()),
			// CL.0 is an HTTP/1.1 framing attack; never negotiate h2.
			NextProtos: []string{"http/1.1"},
		},
	}
	return d.Dial("tcp", addr)
}

func readWireResponse(br *bufio.Reader, method string) (wireResponse, error) {
	resp, err := nethttp.ReadResponse(br, &nethttp.Request{Method: method})
	if err != nil {
		return wireResponse{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, cl0MaxBody+1))
	if err != nil {
		return wireResponse{}, err
	}
	if len(body) > cl0MaxBody {
		return wireResponse{}, errCL0BodyTooLong
	}

	var head strings.Builder
	fmt.Fprintf(&head, "HTTP/%d.%d %s\r\n", resp.ProtoMajor, resp.ProtoMinor, resp.Status)
	_ = resp.Header.Write(&head)
	head.WriteString("\r\n")
	kept := body
	if len(kept) > cl0EvidenceBody {
		kept = kept[:cl0EvidenceBody]
	}
	return wireResponse{
		status: resp.StatusCode,
		closes: resp.Close,
		raw:    head.String() + string(kept),
		body:   string(body),
	}, nil
}

func buildCL0Result(svc *httpmsg.Service, base cl0Baseline, first, second, control cl0Attempt) *output.ResultEvent {
	target := cl0URL(svc, base.path)
	reflected := strings.Contains(first.followUp.body, first.canary) ||
		strings.Contains(second.followUp.body, second.canary)

	collector := modkit.NewEvidenceCollector()
	collector.Add("second attack pair (reproduced with a fresh canary)", second.request, second.followUp.raw)
	collector.Add("control pair (same-length benign body; follow-up answered normally)", control.request, control.followUp.raw)
	collector.Add("baseline: the follow-up's own response on a reused connection", "GET "+base.path, base.own.raw)
	collector.Add("baseline: a random path's response", "GET /<random canary>", base.canary.raw)

	extracted := []string{
		"Probe: CL.0",
		fmt.Sprintf("Follow-up GET %s on the reused connection got %d (the canary's response) instead of its own %d",
			base.path, first.followUp.status, base.own.status),
		fmt.Sprintf("Reproduced with a fresh canary: %d", second.followUp.status),
		fmt.Sprintf("Control pair (benign body of the same length): follow-up got %d", control.followUp.status),
	}
	if reflected {
		extracted = append(extracted, "The follow-up's response body reflects the smuggled canary path")
	}

	return &output.ResultEvent{
		URL:                target,
		Matched:            target,
		Request:            first.request,
		Response:           first.followUp.raw,
		AdditionalEvidence: collector.Entries(),
		ExtractedResults:   extracted,
		Metadata: map[string]any{
			"variant":          "CL.0",
			"path":             base.path,
			"canary":           first.canary,
			"own_status":       base.own.status,
			"canary_status":    base.canary.status,
			"followup_status":  first.followUp.status,
			"control_status":   control.followUp.status,
			"canary_reflected": reflected,
			"connection_reuse": true,
		},
		Info: output.Info{
			Name: "HTTP Request Smuggling: CL.0 Desync",
			Description: "CL.0 desync: the server ignored the Content-Length of a POST to " + base.path +
				" and parsed its body as the start of the next request. A follow-up GET on the same " +
				"connection was answered with the smuggled request's response, so a front-end sharing " +
				"back-end connections lets an attacker prefix other users' requests.",
			// Observed on a second request, twice, against a benign control -
			// stronger than the timing probes, but a single direct connection
			// cannot show which hop ignores the length, so not Certain.
			Severity:   severity.High,
			Confidence: severity.Firm,
		},
	}
}

func cl0URL(svc *httpmsg.Service, path string) string {
	host := svc.Host()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := svc.Port()
	if (svc.Protocol() == "https" && port == 443) || (svc.Protocol() == "http" && port == 80) {
		return svc.Protocol() + "://" + host + path
	}
	return fmt.Sprintf("%s://%s:%d%s", svc.Protocol(), host, port, path)
}
