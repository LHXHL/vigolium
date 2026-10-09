package h2race

import (
	"net"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// replayDropHeaders are captured headers the transports own: framing,
// connection management and anything HTTP/2 forbids. accept-encoding is
// dropped too so evidence bodies stay readable.
var replayDropHeaders = map[string]bool{
	"host":              true,
	"content-length":    true,
	"transfer-encoding": true,
	"connection":        true,
	"keep-alive":        true,
	"proxy-connection":  true,
	"upgrade":           true,
	"te":                true,
	"expect":            true,
	"http2-settings":    true,
	"accept-encoding":   true,
}

// FromCaptured converts a captured request into a Target and a Request that
// replays it faithfully over either transport: same method, path, query,
// headers (minus replayDropHeaders) and body, with a correct content-length.
// ok is false when the capture has no request or service.
func FromCaptured(rr *httpmsg.HttpRequestResponse) (Target, Request, bool) {
	if rr == nil || rr.Request() == nil || rr.Service() == nil {
		return Target{}, Request{}, false
	}
	req, svc := rr.Request(), rr.Service()
	tls := strings.EqualFold(svc.Protocol(), "https")
	t := Target{Host: svc.Host(), Port: svc.Port(), TLS: tls}

	authority := strings.TrimSpace(req.Header("Host"))
	if authority == "" {
		authority = svc.Host()
		if (tls && svc.Port() != 443) || (!tls && svc.Port() != 80) {
			authority = net.JoinHostPort(svc.Host(), strconv.Itoa(svc.Port()))
		}
	}
	scheme := "http"
	if tls {
		scheme = "https"
	}
	out := Request{
		Method:    req.Method(),
		Scheme:    scheme,
		Authority: authority,
		Path:      req.Path(),
		Body:      append([]byte(nil), req.Body()...),
	}
	for _, h := range req.Headers() {
		name := strings.TrimSpace(h.Name)
		if name == "" || strings.HasPrefix(name, ":") || replayDropHeaders[strings.ToLower(name)] {
			continue
		}
		out.Header = append(out.Header, Header{Name: name, Value: h.Value})
	}
	if len(out.Body) > 0 || methodCarriesBody(out.Method) {
		out.Header = append(out.Header, Header{Name: "Content-Length", Value: strconv.Itoa(len(out.Body))})
	}
	return t, out, true
}
