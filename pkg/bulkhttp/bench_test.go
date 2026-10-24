package bulkhttp

import (
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// BenchmarkTransportThroughput measures completed requests per second through
// a Transport, per protocol, against an in-process origin answering a small
// 404-sized body - the shape of a wordlist miss. It is a regression harness
// for the client's own per-request cost, not a prediction of any remote rate:
// over loopback there is no latency to hide and client and origin share the
// CPU, so HTTP/1.1 over one socket per in-flight request is the cheapest per
// request. What multiplexing buys shows in the conns metric: the same
// in-flight load on one or two connections instead of one per request, which
// is what lets discovery and fuzz raise their concurrency against a real
// origin without opening a socket (and a TLS handshake) for each.
//
//	go test -run '^$' -bench TransportThroughput -benchtime 20000x ./pkg/bulkhttp/
//
// Add -cpuprofile/-memprofile to see where a protocol spends its time.
func BenchmarkTransportThroughput(b *testing.B) {
	body := []byte("<html><body><h1>404 Not Found</h1><p>The requested URL was not found on this server.</p></body></html>")
	for _, tc := range []struct {
		name   string
		mode   Mode
		h2, h3 bool
	}{
		{"http1", ModeHTTP1, false, false},
		{"http2", ModeHTTP2, true, false},
		{"http3", ModeHTTP3, true, true},
	} {
		for _, inFlight := range []int{16, 128} {
			b.Run(tc.name+"/inflight="+strconv.Itoa(inFlight), func(b *testing.B) {
				o := startOrigin(b, tc.h2, tc.h3, func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "text/html")
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write(body)
				})
				tr := New(Config{
					Base:         benchBase(inFlight),
					Mode:         tc.mode,
					ProbeTimeout: time.Second,
				})
				defer tr.Close()
				client := &http.Client{Transport: tr, Timeout: 30 * time.Second}
				target := o.URL.String() + "/miss"

				// Warm the origin's protocol decision and first connection.
				if resp, err := client.Get(target); err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
				} else {
					b.Fatalf("warm-up: %v", err)
				}

				var failed atomic.Int64
				work := make(chan struct{}, inFlight)
				done := make(chan struct{})
				b.ResetTimer()
				start := time.Now()
				go func() {
					for i := 0; i < b.N; i++ {
						work <- struct{}{}
					}
					close(work)
				}()
				for w := 0; w < inFlight; w++ {
					go func() {
						for range work {
							resp, err := client.Get(target)
							if err != nil {
								failed.Add(1)
								continue
							}
							_, _ = io.Copy(io.Discard, resp.Body)
							_ = resp.Body.Close()
						}
						done <- struct{}{}
					}()
				}
				for w := 0; w < inFlight; w++ {
					<-done
				}
				elapsed := time.Since(start)
				b.StopTimer()
				// HTTP/1.1 at high in-flight churns hundreds of loopback sockets
				// and can lose the odd one; report errors, fail only past 1%.
				f := failed.Load()
				b.ReportMetric(float64(f), "errors")
				if f*100 > int64(b.N) {
					b.Fatalf("%d of %d requests failed", f, b.N)
				}
				b.ReportMetric(float64(b.N)/elapsed.Seconds(), "req/s")
				b.ReportMetric(float64(o.tcpConns.Load()+int64(o.h3ConnCount())), "conns")
			})
		}
	}
}

func benchBase(inFlight int) *http.Transport {
	t := newTestBase()
	t.MaxIdleConns = inFlight * 2
	t.MaxIdleConnsPerHost = inFlight
	return t
}
