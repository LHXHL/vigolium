package http

import (
	"context"
	"fmt"
	nethttp "net/http"
	"time"

	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// Client wraps nethttp.Client with middleware chain support.
// Implements the HTTPClient interface.
type Client struct {
	client     *nethttp.Client
	middleware []Middleware

	// ownedTransport is the base transport NewClient built for this client, kept
	// so CloseIdleConnections can reach it directly. The client's Transport field
	// is the OUTERMOST middleware wrapper, not this transport, so going through
	// it would depend on every middleware in the chain forwarding the call.
	// nil when the client was built around a caller-supplied round tripper.
	ownedTransport *nethttp.Transport
}

// Middleware represents an HTTP middleware function.
// It wraps an nethttp.RoundTripper to add functionality (retry, timeout, rate-limit).
type Middleware func(nethttp.RoundTripper) nethttp.RoundTripper

// ClientConfig configures the HTTP client.
type ClientConfig struct {
	// PoolConfig configures connection pooling
	PoolConfig *PoolConfig

	// Middleware chain (applied in order)
	Middleware []Middleware

	// MaxRedirects limits the number of redirects to follow
	// 0 means no redirects, -1 means unlimited
	// Default: 10
	MaxRedirects int

	// DisableAutoRedirect completely disables automatic redirect following
	// When true, the client will return the redirect response instead of following it
	// This allows manual redirect handling for trailing slash detection
	DisableAutoRedirect bool

	// RequestTimeout is the maximum duration for a request (entire round trip).
	// Default: 0 (no timeout) unless provided by caller (e.g., config.Engine.Timeout).
	RequestTimeout time.Duration

	// Jar specifies the cookie jar for storing and sending cookies.
	// If nil, cookies are not sent with requests and not stored from responses.
	Jar nethttp.CookieJar
}

// DefaultClientConfig returns default client configuration.
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		PoolConfig:   DefaultPoolConfig(),
		Middleware:   []Middleware{},
		MaxRedirects: 10,
		// RequestTimeout defaults to 0 (use nethttp.Client default) so we defer to caller configuration.
	}
}

// NewClient creates a new HTTP client with the specified configuration.
func NewClient(config *ClientConfig) *Client {
	if config == nil {
		config = DefaultClientConfig()
	}
	if config.PoolConfig == nil {
		config.PoolConfig = DefaultPoolConfig()
	}

	// Create base transport
	transport := config.PoolConfig.NewTransport()

	// Apply middleware chain (reverse order so they execute in config order)
	var rt nethttp.RoundTripper = transport
	for i := len(config.Middleware) - 1; i >= 0; i-- {
		rt = config.Middleware[i](rt)
	}

	// Create nethttp.Client
	client := &nethttp.Client{
		Transport: rt,
		Timeout:   config.RequestTimeout,
		Jar:       config.Jar,
		CheckRedirect: func(req *nethttp.Request, via []*nethttp.Request) error {
			// If auto-redirect is disabled, never follow redirects
			if config.DisableAutoRedirect {
				return nethttp.ErrUseLastResponse
			}
			// Follow redirects up to MaxRedirects
			if config.MaxRedirects >= 0 && len(via) >= config.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", config.MaxRedirects)
			}
			return nil
		},
	}

	return &Client{
		client:         client,
		middleware:     config.Middleware,
		ownedTransport: transport,
	}
}

// CloseIdleConnections releases the keep-alive connections this client owns but
// is no longer using. Call it when the component that built the client is done
// with it — idle sockets otherwise sit open until the process exits, which on a
// run that discovers many hosts means one leaked pool per host.
//
// Safe to call more than once, and safe on a client still in use: an in-flight
// request's connection is not idle, so it is untouched.
//
// Only for an OWNED client. A borrowed one belongs to whoever built it; closing
// its idle connections would drop sockets out from under the other user.
//
// Goes straight to the transport that holds the pool rather than through
// c.client, so it cannot be defeated by a middleware that forgets to forward
// the call. (The middlewares do forward it — see middleware.go — but that path
// exists for callers holding the bare client from HTTPClient(), not for this
// one, which knows exactly which transport it built.)
func (c *Client) CloseIdleConnections() {
	if c == nil || c.ownedTransport == nil {
		return
	}
	c.ownedTransport.CloseIdleConnections()
}

// HTTPClient returns the underlying *nethttp.Client.
// This is useful for components that need direct access to the standard library client.
func (c *Client) HTTPClient() *nethttp.Client {
	return c.client
}

// Send sends an HTTP request and returns a ResponseChain.
// Implements domainhttp.HTTPClient interface.
// CRITICAL: Caller MUST call Close() on the returned ResponseChain when done.
//
// ctx is authoritative: it is attached to the outgoing request, overriding
// whatever context the request was built with. RequestBuilder defaults to
// context.Background(), and the startup probe and robots loader both build such
// a request and then pass e.ctx here — so before ctx was attached, cancelling a
// discovery run left every in-flight request running until the client's own
// timeout elapsed. Ctrl-C appeared to hang.
func (c *Client) Send(ctx context.Context, req *nethttp.Request) (*responsechain.ResponseChain, error) {
	// Set default User-Agent if not already set (configured global override
	// or the built-in Chrome string for WAF-bypass realism)
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", httpmsg.DefaultUserAgent())
	}

	// Clone rather than mutate: the caller owns req, and WithContext on a shared
	// request would publish our context to whoever else holds it. Clone is
	// shallow on the body, which is correct here — this is the only send.
	if ctx != nil && ctx != req.Context() {
		req = req.WithContext(ctx)
	}

	// Execute request
	start := time.Now()
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, &RequestError{
			URL: req.URL.String(),
			Err: err,
		}
	}
	elapsed := time.Since(start)

	// Create ResponseChain and fill buffers
	rc := responsechain.NewResponseChain(resp, 0)
	rc.SetDuration(elapsed)
	if err := rc.Fill(); err != nil {
		rc.Close()
		return nil, &RequestError{
			URL: req.URL.String(),
			Err: err,
		}
	}

	return rc, nil // Caller owns rc, MUST call Close()
}
