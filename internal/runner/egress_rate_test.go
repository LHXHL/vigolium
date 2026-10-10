package runner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core/network"
	deparoshttp "github.com/vigolium/vigolium/pkg/deparos/http"
	vighttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

// TestRateLimitGlobal drives the scan's real egress wiring against two local
// hosts at once: the dynamic-assessment requester under --rate-limit, and two
// concurrent discovery targets under discovery.rate_limit.
//
//   - --rate-limit is one bucket across hosts (the requester).
//   - discovery.rate_limit is one bucket across concurrent discovery targets
//     (it had become per target when targets started running concurrently).
//   - both count into the one scan-wide wire-attempt counter.
func TestRateLimitGlobal(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test (~2s)")
	}
	var hits atomic.Int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	srvA := httptest.NewServer(handler)
	defer srvA.Close()
	srvB := httptest.NewServer(handler)
	defer srvB.Close()
	bases := []string{srvA.URL, srvB.URL}

	opts := types.DefaultOptions()
	opts.Silent = true
	opts.Retries = 0
	opts.RateLimit = 10 // burst 10: 25 requests need >= 1.5s
	opts.RateLimitExplicitlySet = true
	opts.Targets = bases
	if err := network.Init(opts); err != nil {
		t.Fatalf("network.Init: %v", err)
	}
	r := &Runner{options: opts, settings: paceSettings(func(p *config.ScanningPaceConfig) {
		p.Discovery.RateLimit = 5 // burst 5: 15 requests need >= 2s
	})}
	infra, err := r.buildInfrastructure(context.Background(), NativeScanPlan{})
	if err != nil {
		t.Fatalf("buildInfrastructure: %v", err)
	}
	defer infra.Close()
	if infra.svc.Egress == nil {
		t.Fatal("buildInfrastructure must build the scan's egress gate")
	}

	const daRequests, discRequests = 25, 15
	var wg sync.WaitGroup
	var daElapsed, discElapsed time.Duration

	// Dynamic assessment: four workers over both hosts.
	wg.Add(1)
	go func() {
		defer wg.Done()
		start := time.Now()
		var next atomic.Int64
		var inner sync.WaitGroup
		for w := 0; w < 4; w++ {
			inner.Add(1)
			go func() {
				defer inner.Done()
				for i := next.Add(1); i <= daRequests; i = next.Add(1) {
					in, err := httpmsg.GetRawRequestFromURL(bases[i%2] + "/da")
					if err != nil {
						t.Error(err)
						return
					}
					resp, _, err := infra.httpRequester.Execute(in, vighttp.Options{NoClustering: true})
					if err != nil {
						t.Errorf("DA request: %v", err)
						return
					}
					resp.Close()
				}
			}()
		}
		inner.Wait()
		daElapsed = time.Since(start)
	}()

	// Discovery: one engine client per target, both through ONE phase hook.
	wg.Add(1)
	go func() {
		defer wg.Done()
		hook := discoveryEgress(infra, r.discoveryRateLimit())
		start := time.Now()
		var next atomic.Int64
		var inner sync.WaitGroup
		for _, base := range bases {
			client := deparoshttp.NewClient(&deparoshttp.ClientConfig{
				Middleware: []deparoshttp.Middleware{
					deparoshttp.RetryMiddleware(deparoshttp.DefaultRetryConfig()),
					hook,
				},
				DisableAutoRedirect: true,
			})
			inner.Add(1)
			go func(base string) {
				defer inner.Done()
				defer client.CloseIdleConnections()
				for next.Add(1) <= discRequests {
					req, _ := http.NewRequestWithContext(context.Background(), "GET", base+"/disc", nil)
					rc, err := client.Send(context.Background(), req)
					if err != nil {
						t.Errorf("discovery request: %v", err)
						return
					}
					rc.Close()
				}
			}(base)
		}
		inner.Wait()
		discElapsed = time.Since(start)
	}()
	wg.Wait()

	if daElapsed < 1300*time.Millisecond {
		t.Errorf("%d DA requests over two hosts at 10/s took %v; want >= ~1.5s (rate not global)", daRequests, daElapsed)
	}
	if discElapsed < 1800*time.Millisecond {
		t.Errorf("%d discovery requests over two targets at 5/s took %v; want >= ~2s (rate per target)", discRequests, discElapsed)
	}
	if got, want := infra.svc.Egress.Sent(), int64(daRequests+discRequests); got != want {
		t.Errorf("scan-wide wire attempts = %d, want %d", got, want)
	}
	if hits.Load() != daRequests+discRequests {
		t.Errorf("servers saw %d requests, want %d", hits.Load(), daRequests+discRequests)
	}
}
