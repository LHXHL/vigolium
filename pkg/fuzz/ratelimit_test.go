package fuzz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/replay"
)

// TestRunRateLimitCoversEverySend checks the cap is run-wide, smooth, and
// applied to the baseline samples and calibration probes as well as payloads:
// a WAF counts all of them.
func TestRunRateLimitCoversEverySend(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	raw := []byte("GET /?q=FUZZ HTTP/1.1\r\nHost: " + host + "\r\n\r\n")

	payloads := make([]string, 24)
	for i := range payloads {
		payloads[i] = "p" + strconv.Itoa(i)
	}
	positions, err := ResolvePositions(raw, Selectors{})
	if err != nil {
		t.Fatal(err)
	}
	const rps = 50.0
	job := Job{
		Raw: raw, Scheme: "http", Hostname: host, Port: port,
		Positions: positions, Payloads: payloads,
		BaselineSamples: 2,
		AutoCalibrate:   true,
		Client:          replay.NewDefaultClient(nil, 5*time.Second),
		// Far more workers than the rate: concurrency must not buy throughput
		// past the cap.
		Concurrency: 16,
		RateLimit:   rps,
	}
	start := time.Now()
	report, err := Run(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)

	sends := int64(len(payloads) + job.BaselineSamples + len(calibrationProbes))
	if got := hits.Load(); got != sends {
		t.Fatalf("server saw %d requests, want %d (payloads + baseline + calibration)", got, sends)
	}
	if report.Sent != len(payloads) {
		t.Fatalf("report.Sent = %d, want %d", report.Sent, len(payloads))
	}
	// Burst 1: n sends need (n-1)/rps of wall clock at minimum.
	floor := time.Duration(float64(sends-1)/rps*float64(time.Second)) - 50*time.Millisecond
	if elapsed < floor {
		t.Fatalf("%d sends at %v rps took %v, want ≥ %v — the limiter is not covering every send", sends, rps, elapsed, floor)
	}
}

func TestRunRateLimitHonoursCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	raw := []byte("GET /?q=FUZZ HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
	positions, _ := ResolvePositions(raw, Selectors{})

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _ = Run(ctx, Job{
		Raw: raw, Scheme: "http", Hostname: host, Port: port,
		Positions: positions, Payloads: []string{"a", "b", "c", "d", "e", "f"},
		Client:    replay.NewDefaultClient(nil, 5*time.Second),
		RateLimit: 1, // six sends would take five seconds
	})
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("a cancelled run kept waiting on the limiter for %v", elapsed)
	}
}

func TestResolvePositionsOptInSelectors(t *testing.T) {
	get := []byte("GET /a?id=1 HTTP/1.1\r\nHost: h\r\n\r\n")
	post := []byte("POST /a HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n{\"a\":1}")

	// param-name renames the existing parameter.
	ps, err := ResolvePositions(get, Selectors{Mode: "param-name"})
	if err != nil || len(ps) != 1 || ps[0].Label != "PARAM_NAME_URL" || ps[0].Name != "id" {
		t.Fatalf("param-name → %+v, %v", ps, err)
	}
	if got := string(BuildAt(ps[0], get, "uid")); !strings.HasPrefix(got, "GET /a?uid=1 ") {
		t.Errorf("rename built %q", got)
	}

	// new-param adds one; the location is inferred, or pinned by qualifier.
	for _, tc := range []struct {
		raw   []byte
		mode  string
		label string
		want  string
	}{
		{get, "new-param", "NEW_PARAM_QUERY", "GET /a?id=1&debug="},
		{get, "param-add:query", "NEW_PARAM_QUERY", "GET /a?id=1&debug="},
		{post, "new-param", "NEW_PARAM_JSON", `"debug":`},
		{get, "new-param:body", "NEW_PARAM_BODY", "\r\n\r\ndebug="},
	} {
		ps, err := ResolvePositions(tc.raw, Selectors{Mode: tc.mode})
		if err != nil || len(ps) != 1 {
			t.Fatalf("%s → %+v, %v", tc.mode, ps, err)
		}
		if ps[0].Label != tc.label || ps[0].Name != "<new>" {
			t.Errorf("%s label/name = %s/%s", tc.mode, ps[0].Label, ps[0].Name)
		}
		if got := string(BuildAt(ps[0], tc.raw, "debug")); !strings.Contains(got, tc.want) {
			t.Errorf("%s built %q, want it to contain %q", tc.mode, got, tc.want)
		}
	}

	// body replaces the entire body.
	ps, err = ResolvePositions(post, Selectors{Mode: "body"})
	if err != nil || len(ps) != 1 || ps[0].Label != "ENTIRE_BODY" {
		t.Fatalf("body → %+v, %v", ps, err)
	}
	if got := string(BuildAt(ps[0], post, "<x/>")); !strings.HasSuffix(got, "\r\n\r\n<x/>") || !strings.Contains(got, "Content-Length: 4") {
		t.Errorf("body built %q", got)
	}

	// The default selector keeps the scanner's set: no opt-in kinds.
	all, err := ResolvePositions(get, Selectors{})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range all {
		if strings.HasPrefix(p.Label, "PARAM_NAME") || strings.HasPrefix(p.Label, "NEW_PARAM") || p.Label == "ENTIRE_BODY" {
			t.Errorf("default selector produced opt-in position %s", p.Label)
		}
	}

	// Errors name the fix.
	if _, err := ResolvePositions(get, Selectors{Mode: "body"}); err == nil || !strings.Contains(err.Error(), "-d") {
		t.Errorf("bodiless --fuzz body: %v", err)
	}
	if _, err := ResolvePositions(get, Selectors{Mode: "new-param:xml"}); err == nil {
		t.Error("unknown new-param location accepted")
	}
	if _, err := ResolvePositions(get, Selectors{Mode: "headers:x"}); err == nil {
		t.Error("qualifier on a selector that takes none accepted")
	}
}

func TestExpandSuffixes(t *testing.T) {
	got := ExpandSuffixes([]string{"admin", "admin.php", "index"}, []string{".php", ".bak"})
	want := []string{"admin", "admin.php", "admin.bak", "admin.php.php", "admin.php.bak", "index", "index.php", "index.bak"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("got %v\nwant %v", got, want)
	}
	if got := ExpandSuffixes([]string{"a"}, nil); len(got) != 1 {
		t.Errorf("no suffixes changed the list: %v", got)
	}
}

func TestBuiltinParamsWordlist(t *testing.T) {
	got, err := LoadPayloads([]string{"params"}, nil, nil)
	if err != nil || len(got) < 100 {
		t.Fatalf("builtin params: %d names, %v", len(got), err)
	}
}
