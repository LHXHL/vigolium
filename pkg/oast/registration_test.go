package oast

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	interactshclient "github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/vigolium/vigolium/internal/config"
)

// blackholeServer accepts TCP connections and never answers, the way a
// firewalled or wedged interactsh server looks to a client. Accepted
// connections are held open until the test ends.
func blackholeServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return "http://" + ln.Addr().String()
}

// withRegistrationTimeout shortens the registration bound for one test.
func withRegistrationTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	prev := registrationTimeout
	registrationTimeout = d
	t.Cleanup(func() { registrationTimeout = prev })
}

// withClientFactory replaces the interactsh constructor for one test.
func withClientFactory(t *testing.T, f func(*interactshclient.Options) (*interactshclient.Client, error)) {
	t.Helper()
	prev := newInteractshClient
	newInteractshClient = f
	t.Cleanup(func() { newInteractshClient = prev })
}

// TestNew_BlackholeServerDoesNotBlock is the point of async registration: a
// server that never answers must not hold up New, and until registration
// resolves the service reports itself unavailable rather than handing out
// callback hosts nobody is polling.
func TestNew_BlackholeServerDoesNotBlock(t *testing.T) {
	withRegistrationTimeout(t, 1500*time.Millisecond)
	server := blackholeServer(t)

	start := time.Now()
	svc, err := New(&config.OASTConfig{Enabled: true, ServerURL: server}, nil, nil, "", "", nil)
	if err != nil || svc == nil {
		t.Fatalf("New = (%v, %v), want a registering service", svc, err)
	}
	t.Cleanup(svc.Close)
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Errorf("New took %s against a blackhole server, want < 50ms", elapsed)
	}

	if svc.Enabled() {
		t.Error("Enabled() = true while registering")
	}
	if got := svc.GenerateURL("http://t", "p", "x", "m", ""); got != "" {
		t.Errorf("GenerateURL while registering = %q, want \"\"", got)
	}

	waitStart := time.Now()
	err = svc.WaitReady(context.Background(), 300*time.Millisecond)
	if !errors.Is(err, ErrNotReady) {
		t.Fatalf("WaitReady before the registration timeout = %v, want ErrNotReady", err)
	}
	if elapsed := time.Since(waitStart); elapsed > time.Second {
		t.Errorf("WaitReady(300ms) took %s", elapsed)
	}

	// Once the registration request times out, the failure is final and says why.
	err = svc.WaitReady(context.Background(), 5*time.Second)
	var uerr *UnavailableError
	if !errors.As(err, &uerr) || errors.Is(err, ErrNotReady) {
		t.Fatalf("WaitReady after the registration timeout = %v, want a registration failure", err)
	}
	if uerr.Reason != "dial timeout" {
		t.Errorf("reason = %q, want \"dial timeout\" (full error: %v)", uerr.Reason, uerr.Err)
	}
	if !strings.HasPrefix(err.Error(), server+": ") {
		t.Errorf("error %q should name the server", err.Error())
	}
	if svc.Enabled() {
		t.Error("Enabled() = true after a failed registration")
	}
}

// TestWaitReady_HonoursContext: a cancelled caller is not held for the full wait.
func TestWaitReady_HonoursContext(t *testing.T) {
	withRegistrationTimeout(t, 2*time.Second)
	svc, _ := New(&config.OASTConfig{Enabled: true, ServerURL: blackholeServer(t)}, nil, nil, "", "", nil)
	t.Cleanup(svc.Close)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := svc.WaitReady(ctx, time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitReady with a cancelled ctx = %v, want context.Canceled", err)
	}
}

func TestNew_RegistersAgainstAnsweringServer(t *testing.T) {
	srv, _ := fakeInteractshServer(t)

	svc, err := New(&config.OASTConfig{Enabled: true, ServerURL: srv.URL}, nil, nil, "", "", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(svc.Close)
	if err := svc.WaitReady(context.Background(), 5*time.Second); err != nil {
		t.Fatalf("WaitReady: %v", err)
	}
	if !svc.Enabled() {
		t.Fatal("Enabled() = false after registration")
	}
	host := strings.TrimPrefix(srv.URL, "http://")
	if got := svc.GenerateURL("http://t", "p", "x", "m", ""); !strings.HasSuffix(got, "."+host) {
		t.Errorf("GenerateURL = %q, want a host under %s", got, host)
	}
}

func TestNew_FixedURLIsReadyImmediately(t *testing.T) {
	svc, err := New(&config.OASTConfig{Enabled: true, OastURL: "cb.example.test"}, nil, nil, "", "", nil)
	if err != nil || svc == nil {
		t.Fatalf("New = (%v, %v)", svc, err)
	}
	if err := svc.WaitReady(context.Background(), 0); err != nil {
		t.Errorf("WaitReady in fixed-URL mode = %v, want nil", err)
	}
	if !svc.Enabled() {
		t.Error("Enabled() = false in fixed-URL mode")
	}
	if got := svc.GenerateURL("", "", "", "", ""); got != "cb.example.test" {
		t.Errorf("GenerateURL = %q, want the fixed URL", got)
	}
	called := false
	svc.OnUnavailable(func(error) { called = true })
	if called {
		t.Error("OnUnavailable fired in fixed-URL mode")
	}
	svc.Close()
}

// TestFlush_SkipsGraceWhenNothingMinted: a scan that planted no blind payload
// has nothing to wait for, so Flush must not sleep the grace period.
func TestFlush_SkipsGraceWhenNothingMinted(t *testing.T) {
	srv, _ := fakeInteractshServer(t)
	svc, _ := New(&config.OASTConfig{Enabled: true, ServerURL: srv.URL, GracePeriod: 30}, nil, nil, "", "", nil)
	t.Cleanup(svc.Close)
	if err := svc.WaitReady(context.Background(), 5*time.Second); err != nil {
		t.Fatalf("WaitReady: %v", err)
	}

	start := time.Now()
	svc.Flush()
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("Flush with nothing minted took %s, want immediate", elapsed)
	}
}

func TestFlush_WaitsGraceAfterMint(t *testing.T) {
	srv, _ := fakeInteractshServer(t)
	svc, _ := New(&config.OASTConfig{Enabled: true, ServerURL: srv.URL, GracePeriod: 1}, nil, nil, "", "", nil)
	t.Cleanup(svc.Close)
	if err := svc.WaitReady(context.Background(), 5*time.Second); err != nil {
		t.Fatalf("WaitReady: %v", err)
	}
	if svc.GenerateURL("http://t", "p", "x", "m", "") == "" {
		t.Fatal("GenerateURL returned \"\" after registration")
	}

	start := time.Now()
	svc.Flush()
	if elapsed := time.Since(start); elapsed < 900*time.Millisecond {
		t.Errorf("Flush after a mint took %s, want the 1s grace period", elapsed)
	}
	// The mint was accounted for by that flush; the next round planted nothing.
	start = time.Now()
	svc.Flush()
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("second Flush took %s, want immediate", elapsed)
	}
}

func TestOnUnavailable_FiresOnceOnFailure(t *testing.T) {
	gate := make(chan struct{})
	boom := errors.New("dial tcp 10.0.0.1:443: connect: connection refused")
	withClientFactory(t, func(*interactshclient.Options) (*interactshclient.Client, error) {
		<-gate
		return nil, boom
	})

	svc, _ := New(&config.OASTConfig{Enabled: true, ServerURL: "oast.example.test"}, nil, nil, "", "", nil)
	t.Cleanup(svc.Close)

	var before, after atomic.Int32
	var got error
	var mu sync.Mutex
	svc.OnUnavailable(func(err error) {
		before.Add(1)
		mu.Lock()
		got = err
		mu.Unlock()
	})
	close(gate)
	if err := svc.WaitReady(context.Background(), 5*time.Second); err == nil {
		t.Fatal("WaitReady = nil after a failed registration")
	}
	// Registered after the failure: runs immediately.
	svc.OnUnavailable(func(error) { after.Add(1) })

	if before.Load() != 1 || after.Load() != 1 {
		t.Fatalf("callbacks fired before=%d after=%d, want 1 and 1", before.Load(), after.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	var uerr *UnavailableError
	if !errors.As(got, &uerr) || uerr.Reason != "connection refused" || !errors.Is(got, boom) {
		t.Errorf("callback error = %v, want an UnavailableError wrapping the cause with reason \"connection refused\"", got)
	}
}

// TestClose_DuringRegistrationDeregisters: Close while registration is still in
// flight must not leave a polling client behind once registration lands.
func TestClose_DuringRegistrationDeregisters(t *testing.T) {
	var deregistered atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/deregister" {
			deregistered.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"registration successful"}`))
	}))
	t.Cleanup(srv.Close)

	gate := make(chan struct{})
	withClientFactory(t, func(o *interactshclient.Options) (*interactshclient.Client, error) {
		<-gate
		return interactshclient.New(o)
	})

	svc, _ := New(&config.OASTConfig{Enabled: true, ServerURL: srv.URL}, nil, nil, "", "", nil)
	svc.Close()
	close(gate)

	if err := svc.WaitReady(context.Background(), 5*time.Second); !errors.Is(err, ErrClosed) {
		t.Fatalf("WaitReady after Close = %v, want ErrClosed", err)
	}
	if svc.Enabled() {
		t.Error("Enabled() = true after Close during registration")
	}
	if deregistered.Load() != 1 {
		t.Errorf("/deregister requests = %d, want 1", deregistered.Load())
	}
}

// TestRegistration_ConcurrentReaders exercises the atomic client hand-off under
// -race: modules read Enabled/GenerateURL while the registration goroutine
// publishes the client.
func TestRegistration_ConcurrentReaders(t *testing.T) {
	srv, _ := fakeInteractshServer(t)
	svc, _ := New(&config.OASTConfig{Enabled: true, ServerURL: srv.URL}, nil, nil, "", "", nil)
	t.Cleanup(svc.Close)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if svc.Enabled() {
					if u := svc.GenerateURL("http://t", "p", "x", "m", ""); u != "" {
						svc.RecordPayload(u, "payload")
					}
				}
			}
		}()
	}
	if err := svc.WaitReady(context.Background(), 5*time.Second); err != nil {
		t.Errorf("WaitReady: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func TestBriefRegistrationError(t *testing.T) {
	for in, want := range map[string]string{
		`could not register to server: Post "https://oast.pro/register": context deadline exceeded (Client.Timeout exceeded while awaiting headers)`: "dial timeout",
		`dial tcp 127.0.0.1:1: connect: connection refused`: "connection refused",
		`dial tcp: lookup oast.invalid: no such host`:       "dns lookup failed",
		`invalid token provided for interactsh server`:      "invalid token",
		`http: server gave HTTP response to HTTPS client`:   "tls handshake failed",
		`something odd`: "something odd",
	} {
		if got := briefRegistrationError(errors.New(in)); got != want {
			t.Errorf("briefRegistrationError(%q) = %q, want %q", in, got, want)
		}
	}
}
