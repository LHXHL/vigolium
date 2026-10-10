package network

import (
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/proto"
	"github.com/ysmood/gson"
)

func wireHeaders(kv ...string) proto.NetworkHeaders {
	h := proto.NetworkHeaders{}
	for i := 0; i+1 < len(kv); i += 2 {
		h[kv[i]] = gson.New(kv[i+1])
	}
	return h
}

func extraInfo(reqID string, kv ...string) *proto.NetworkRequestWillBeSentExtraInfo {
	return &proto.NetworkRequestWillBeSentExtraInfo{
		RequestID: proto.NetworkRequestID(reqID),
		Headers:   wireHeaders(kv...),
	}
}

func rwbs(reqID, method, rawURL string, headers proto.NetworkHeaders, redirect *proto.NetworkResponse) *proto.NetworkRequestWillBeSent {
	return &proto.NetworkRequestWillBeSent{
		RequestID:        proto.NetworkRequestID(reqID),
		Type:             proto.NetworkResourceTypeXHR,
		Request:          &proto.NetworkRequest{Method: method, URL: rawURL, Headers: headers},
		RedirectResponse: redirect,
	}
}

func finished(reqID string) *proto.NetworkLoadingFinished {
	return &proto.NetworkLoadingFinished{RequestID: proto.NetworkRequestID(reqID)}
}

// entryFor returns the written entry for rawURL, failing the test when absent.
func (m *mockWriter) entryFor(t *testing.T, rawURL string) *TrafficEntry {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.entries {
		if e.Request.URL == rawURL {
			return e
		}
	}
	t.Fatalf("no entry written for %s", rawURL)
	return nil
}

func headerValue(h map[string]string, name string) (string, bool) {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

func TestExtraInfoBeforeRequestWillBeSent(t *testing.T) {
	mock := &mockWriter{}
	c := newRedirectTestCapture(mock)
	const u = "https://app.example.com/api/me"

	c.onRequestWillBeSentExtraInfo(extraInfo("1", "Cookie", "sid=abc", "Host", "app.example.com"))
	c.onRequestWillBeSent(rwbs("1", "GET", u, wireHeaders("Accept", "*/*"), nil), "s")
	c.onLoadingFinished(finished("1"), "s")

	e := mock.entryFor(t, u)
	if v, _ := headerValue(e.Request.Headers, "Cookie"); v != "sid=abc" {
		t.Fatalf("Cookie = %q, want sid=abc (headers %v)", v, e.Request.Headers)
	}
	if c.extraParked.len() != 0 {
		t.Fatalf("parked ExtraInfo not consumed: %d left", c.extraParked.len())
	}
}

func TestExtraInfoAfterRequestWillBeSent(t *testing.T) {
	mock := &mockWriter{}
	c := newRedirectTestCapture(mock)
	const u = "https://app.example.com/api/me"

	c.onRequestWillBeSent(rwbs("1", "GET", u, wireHeaders("Accept", "*/*"), nil), "s")
	c.onRequestWillBeSentExtraInfo(extraInfo("1", "Cookie", "sid=abc"))
	c.onLoadingFinished(finished("1"), "s")

	e := mock.entryFor(t, u)
	if v, _ := headerValue(e.Request.Headers, "Cookie"); v != "sid=abc" {
		t.Fatalf("Cookie = %q, want sid=abc", v)
	}
	if c.extraParked.len() != 0 {
		t.Fatalf("ExtraInfo parked instead of merged")
	}
}

// TestExtraInfoRedirectChain covers a redirect chain sharing one RequestID, with
// each hop's ExtraInfo in a different position relative to its requestWillBeSent.
func TestExtraInfoRedirectChain(t *testing.T) {
	const (
		a = "https://app.example.com/login"
		b = "https://app.example.com/home"
		d = "https://other.example.net/landing"
	)
	tests := []struct {
		name  string
		order func(c *Capture)
	}{
		{"extra after each hop", func(c *Capture) {
			c.onRequestWillBeSent(rwbs("1", "GET", a, nil, nil), "s")
			c.onRequestWillBeSentExtraInfo(extraInfo("1", "Cookie", "hop=0"))
			c.onRequestWillBeSent(rwbs("1", "GET", b, nil, &proto.NetworkResponse{Status: 302}), "s")
			c.onRequestWillBeSentExtraInfo(extraInfo("1", "Cookie", "hop=1"))
			c.onRequestWillBeSent(rwbs("1", "GET", d, nil, &proto.NetworkResponse{Status: 302}), "s")
			c.onRequestWillBeSentExtraInfo(extraInfo("1", "Cookie", "hop=2", "Host", "other.example.net"))
		}},
		{"extra ahead of each hop", func(c *Capture) {
			c.onRequestWillBeSentExtraInfo(extraInfo("1", "Cookie", "hop=0"))
			c.onRequestWillBeSent(rwbs("1", "GET", a, nil, nil), "s")
			// hop 0 already has its ExtraInfo, so this one waits for hop 1.
			c.onRequestWillBeSentExtraInfo(extraInfo("1", "Cookie", "hop=1"))
			c.onRequestWillBeSent(rwbs("1", "GET", b, nil, &proto.NetworkResponse{Status: 302}), "s")
			c.onRequestWillBeSentExtraInfo(extraInfo("1", "Cookie", "hop=2", "Host", "other.example.net"))
			c.onRequestWillBeSent(rwbs("1", "GET", d, nil, &proto.NetworkResponse{Status: 302}), "s")
		}},
		{"cross-host extra ahead of a hop without one", func(c *Capture) {
			c.onRequestWillBeSent(rwbs("1", "GET", a, nil, nil), "s")
			c.onRequestWillBeSentExtraInfo(extraInfo("1", "Cookie", "hop=0", "Host", "app.example.com"))
			c.onRequestWillBeSent(rwbs("1", "GET", b, nil, &proto.NetworkResponse{Status: 302}), "s")
			// hop 1 has no ExtraInfo yet, but this one names hop 2's host.
			c.onRequestWillBeSentExtraInfo(extraInfo("1", "Cookie", "hop=2", ":authority", "other.example.net"))
			c.onRequestWillBeSentExtraInfo(extraInfo("1", "Cookie", "hop=1", "Host", "app.example.com"))
			c.onRequestWillBeSent(rwbs("1", "GET", d, nil, &proto.NetworkResponse{Status: 302}), "s")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockWriter{}
			c := newRedirectTestCapture(mock)
			tt.order(c)
			c.onLoadingFinished(finished("1"), "s")
			for i, u := range []string{a, b, d} {
				e := mock.entryFor(t, u)
				want := fmt.Sprintf("hop=%d", i)
				if v, _ := headerValue(e.Request.Headers, "Cookie"); v != want {
					t.Errorf("hop %d (%s): Cookie = %q, want %q", i, u, v, want)
				}
			}
			if c.extraParked.len() != 0 {
				t.Errorf("parked ExtraInfo left after the chain finished: %d", c.extraParked.len())
			}
		})
	}
}

func TestMergeWireHeadersRule(t *testing.T) {
	dst := map[string]string{
		"User-Agent": "renderer-ua",
		"referer":    "https://renderer.example/",
		"Accept":     "*/*",
	}
	mergeWireHeaders(dst, map[string]string{
		"cookie":          "sid=1",
		"Referer":         "https://wire.example/",
		"Origin":          "https://wire.example",
		"Host":            "wire.example",
		"User-Agent":      "wire-ua",
		"Accept-Encoding": "gzip",
	})
	want := map[string]string{
		"User-Agent": "renderer-ua",
		"referer":    "https://wire.example/",
		"Accept":     "*/*",
		"Cookie":     "sid=1",
		"Origin":     "https://wire.example",
		"Host":       "wire.example",
	}
	if len(dst) != len(want) {
		t.Fatalf("headers = %v, want %v", dst, want)
	}
	for k, v := range want {
		if dst[k] != v {
			t.Errorf("%s = %q, want %q (all: %v)", k, dst[k], v, dst)
		}
	}
}

func TestExtraParkBounds(t *testing.T) {
	var p extraPark
	now := time.Now()
	for i := range extraParkCap + 10 {
		p.put(proto.NetworkRequestID(fmt.Sprint(i)), map[string]string{"Cookie": "x"}, now)
	}
	if p.len() != extraParkCap {
		t.Fatalf("park size = %d, want cap %d", p.len(), extraParkCap)
	}
	if _, ok := p.take("0", "https://a.example/", now); ok {
		t.Fatal("oldest entry should have been evicted")
	}
	if _, ok := p.take(proto.NetworkRequestID(fmt.Sprint(extraParkCap+9)), "https://a.example/", now); !ok {
		t.Fatal("newest entry missing")
	}
	if n := p.expire(now.Add(extraParkTTL + time.Second)); n != extraParkCap-1 {
		t.Fatalf("expired %d, want %d", n, extraParkCap-1)
	}
	if p.len() != 0 {
		t.Fatalf("park not empty after TTL: %d", p.len())
	}

	// A parked hop past its TTL is not adopted.
	p.put("late", map[string]string{"Cookie": "x"}, now)
	if _, ok := p.take("late", "https://a.example/", now.Add(extraParkTTL+time.Second)); ok {
		t.Fatal("expired ExtraInfo adopted")
	}
}

func TestRequestCountersScope(t *testing.T) {
	mock := &mockWriter{}
	c := newRedirectTestCapture(mock)
	c.ScopeFilter = func(host, _ string) bool { return host == "app.example.com" }
	var sent, inScope atomic.Int64
	c.AddRequestCounters(RequestCounters{Sent: &sent, InScope: &inScope})

	c.onRequestWillBeSent(rwbs("1", "GET", "https://app.example.com/", nil, nil), "s")
	c.onRequestWillBeSent(rwbs("2", "GET", "https://cdn.other.net/lib.js", nil, nil), "s")
	c.onRequestWillBeSent(rwbs("3", "GET", "https://app.example.com/b", nil, &proto.NetworkResponse{Status: 302}), "s")
	c.onRequestWillBeSent(rwbs("4", "GET", "data:text/plain,hi", nil, nil), "s") // not network

	if c.RequestsSent() != 3 || c.RequestsSentInScope() != 2 {
		t.Fatalf("capture counters sent=%d inScope=%d, want 3/2", c.RequestsSent(), c.RequestsSentInScope())
	}
	if sent.Load() != 3 || inScope.Load() != 2 {
		t.Fatalf("sink counters sent=%d inScope=%d, want 3/2", sent.Load(), inScope.Load())
	}
}

func postRequest(reqID, rawURL, inline string) *proto.NetworkRequestWillBeSent {
	e := rwbs(reqID, "POST", rawURL, wireHeaders("Content-Type", "multipart/form-data; boundary=x"), nil)
	e.Request.HasPostData = true
	e.Request.PostData = inline
	return e
}

func TestPostDataFetchedLazily(t *testing.T) {
	mock := &mockWriter{}
	c := newRedirectTestCapture(mock)
	c.ScopeFilter = func(host, _ string) bool { return host == "app.example.com" }
	big := strings.Repeat("A", 200*1024)
	var calls atomic.Int64
	c.postDataFetcher = func(_ proto.TargetSessionID, id proto.NetworkRequestID) ([]byte, error) {
		calls.Add(1)
		if id == "fail" {
			return nil, fmt.Errorf("No post data available for the request")
		}
		return []byte(big), nil
	}
	c.startPostDataWorkers()

	// Body omitted by requestWillBeSent: fetched.
	c.onRequestWillBeSent(postRequest("1", "https://app.example.com/upload", ""), "s")
	c.onLoadingFinished(finished("1"), "s")
	// Inline body present: not fetched.
	c.onRequestWillBeSent(postRequest("2", "https://app.example.com/small", "a=1"), "s")
	c.onLoadingFinished(finished("2"), "s")
	// Out of scope: not fetched.
	c.onRequestWillBeSent(postRequest("3", "https://cdn.other.net/beacon", ""), "s")
	c.onLoadingFinished(finished("3"), "s")
	// Static asset path: not fetched.
	c.onRequestWillBeSent(postRequest("4", "https://app.example.com/pixel.png", ""), "s")
	c.onLoadingFinished(finished("4"), "s")
	// Fetch fails: written with what it had.
	c.onRequestWillBeSent(postRequest("fail", "https://app.example.com/gone", ""), "s")
	c.onLoadingFinished(finished("fail"), "s")

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("getRequestPostData calls = %d, want 2", got)
	}
	if e := mock.entryFor(t, "https://app.example.com/upload"); len(e.Request.Body) != len(big) {
		t.Fatalf("fetched body len = %d, want %d", len(e.Request.Body), len(big))
	}
	if e := mock.entryFor(t, "https://app.example.com/small"); string(e.Request.Body) != "a=1" {
		t.Fatalf("inline body = %q", e.Request.Body)
	}
	mock.entryFor(t, "https://app.example.com/gone")
	if fetched, failed, dropped := c.PostDataStats(); fetched != 1 || failed != 1 || dropped != 0 {
		t.Fatalf("stats fetched=%d failed=%d dropped=%d, want 1/1/0", fetched, failed, dropped)
	}
}

func TestPostDataQueueFullDropsAndStillWrites(t *testing.T) {
	mock := &mockWriter{}
	c := newRedirectTestCapture(mock)
	release := make(chan struct{})
	c.postDataFetcher = func(proto.TargetSessionID, proto.NetworkRequestID) ([]byte, error) {
		<-release
		return []byte("body"), nil
	}
	c.startPostDataWorkers()

	total := postDataWorkers + postDataQueue + 5
	for i := range total {
		id := fmt.Sprint(i)
		c.onRequestWillBeSent(postRequest(id, "https://app.example.com/p/"+id, ""), "s")
		c.onLoadingFinished(finished(id), "s")
	}
	// Workers hold postDataWorkers jobs, the queue postDataQueue; the rest
	// overflow. A worker may not have dequeued yet, so at least 5 drop.
	_, _, dropped := c.PostDataStats()
	if dropped < 5 {
		t.Fatalf("dropped = %d, want >= 5", dropped)
	}
	close(release)
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := mock.getWriteCount(); got != total {
		t.Fatalf("written = %d, want every entry (%d)", got, total)
	}
}

func TestPostDataBase64Decode(t *testing.T) {
	got, err := decodePostData([]byte(`{"postData":"AAEC","base64Encoded":true}`))
	if err != nil || string(got) != "\x00\x01\x02" {
		t.Fatalf("decode = %q, %v", got, err)
	}
	got, err = decodePostData([]byte(`{"postData":"a=1"}`))
	if err != nil || string(got) != "a=1" {
		t.Fatalf("decode = %q, %v", got, err)
	}
}

// TestExtraInfoConcurrentDelivery feeds the events of many requests from
// several goroutines in shuffled per-request order. Run under -race.
func TestExtraInfoConcurrentDelivery(t *testing.T) {
	mock := &mockWriter{}
	c := newRedirectTestCapture(mock)
	c.ScopeFilter = func(string, string) bool { return true }
	c.postDataFetcher = func(proto.TargetSessionID, proto.NetworkRequestID) ([]byte, error) {
		return []byte("payload"), nil
	}
	c.startPostDataWorkers()
	var sink atomic.Int64
	c.AddRequestCounters(RequestCounters{Sent: &sink})

	const n = 200
	var wg sync.WaitGroup
	for w := range 8 {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			r := rand.New(rand.NewSource(int64(w)))
			for i := w; i < n; i += 8 {
				id := fmt.Sprint(i)
				u := fmt.Sprintf("https://app.example.com/r/%d", i)
				extraFirst := r.Intn(2) == 0
				if extraFirst {
					c.onRequestWillBeSentExtraInfo(extraInfo(id, "Cookie", "n="+id))
				}
				c.onRequestWillBeSent(postRequest(id, u, ""), "s")
				if !extraFirst {
					c.onRequestWillBeSentExtraInfo(extraInfo(id, "Cookie", "n="+id))
				}
				c.onLoadingFinished(finished(id), "s")
			}
		}(w)
	}
	wg.Wait()
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if sink.Load() != n || c.RequestsSent() != n {
		t.Fatalf("sent = %d / sink %d, want %d", c.RequestsSent(), sink.Load(), n)
	}
	mock.mu.Lock()
	defer mock.mu.Unlock()
	for _, e := range mock.entries {
		id := e.Request.URL[strings.LastIndexByte(e.Request.URL, '/')+1:]
		if v, _ := headerValue(e.Request.Headers, "Cookie"); v != "n="+id {
			t.Errorf("%s: Cookie = %q", e.Request.URL, v)
		}
	}
}
