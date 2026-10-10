package exttest

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// mockRoute is one canned response from <case>.responses/*.http: served for a
// request with this method and path, and (when match is set) containing match
// in its request-target or body. A path with a query matches the full
// request-target; one without matches the path alone. Method "*" or "ANY"
// matches every method.
type mockRoute struct {
	file     string
	method   string
	path     string
	match    string
	response []byte
}

// mockServer answers an active extension's requests from canned responses. It
// listens on 127.0.0.1 only, so a fixture run never leaves the machine.
type mockServer struct {
	srv    *httptest.Server
	routes []mockRoute

	mu        sync.Mutex
	served    int
	unmatched []string
}

// loadMockRoutes reads every .http file in dir as a route. Routes with a
// match substring are tried before the plain method+path ones.
func loadMockRoutes(dir string) ([]mockRoute, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var routes []mockRoute
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".http") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		fx, err := parseHTTPFixture(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if len(fx.Response) == 0 {
			return nil, fmt.Errorf("%s: no response (a mock response file is a request line, a blank line, then the response)", e.Name())
		}
		line, _, _ := strings.Cut(string(fx.Request), "\r\n")
		parts := strings.Fields(line)
		if len(parts) < 2 {
			return nil, fmt.Errorf("%s: bad request line %q (want METHOD /path)", e.Name(), line)
		}
		routes = append(routes, mockRoute{
			file:     e.Name(),
			method:   strings.ToUpper(parts[0]),
			path:     parts[1],
			match:    fx.Directives["match"],
			response: fx.Response,
		})
	}
	sort.SliceStable(routes, func(i, j int) bool {
		return routes[i].match != "" && routes[j].match == ""
	})
	return routes, nil
}

func newMockServer(routes []mockRoute) *mockServer {
	m := &mockServer{routes: routes}
	m.srv = httptest.NewUnstartedServer(http.HandlerFunc(m.serve))
	// httptest already binds 127.0.0.1; make it explicit, since a fixture run
	// must never listen beyond loopback.
	if l, err := net.Listen("tcp", "127.0.0.1:0"); err == nil {
		_ = m.srv.Listener.Close()
		m.srv.Listener = l
	}
	m.srv.Start()
	return m
}

// host is the mock's host:port, what a case request's Host is rewritten to.
func (m *mockServer) host() string { return m.srv.Listener.Addr().String() }

func (m *mockServer) close() { m.srv.Close() }

func (m *mockServer) stats() (served int, unmatched []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.served, append([]string(nil), m.unmatched...)
}

func (m *mockServer) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	target := r.URL.RequestURI()
	m.mu.Lock()
	m.served++
	m.mu.Unlock()

	for _, rt := range m.routes {
		if rt.method != "*" && rt.method != "ANY" && rt.method != r.Method {
			continue
		}
		if strings.Contains(rt.path, "?") {
			if rt.path != target {
				continue
			}
		} else if rt.path != r.URL.Path {
			continue
		}
		if rt.match != "" && !strings.Contains(target, rt.match) && !bytes.Contains(body, []byte(rt.match)) {
			continue
		}
		writeCanned(w, rt.response)
		return
	}

	m.mu.Lock()
	m.unmatched = append(m.unmatched, r.Method+" "+target)
	m.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusNotFound)
	_, _ = fmt.Fprintf(w, "ext test mock: no fixture response for %s %s\n", r.Method, target)
}

// writeCanned writes a raw HTTP response through w: its status, its headers
// (framing headers are recomputed) and its body.
func writeCanned(w http.ResponseWriter, raw []byte) {
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, "ext test mock: unparseable fixture response: %v\n", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	for name, values := range resp.Header {
		if strings.EqualFold(name, "Content-Length") || strings.EqualFold(name, "Transfer-Encoding") {
			continue
		}
		for _, v := range values {
			w.Header().Add(name, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}
