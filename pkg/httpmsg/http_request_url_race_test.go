package httpmsg

import (
	"sync"
	"testing"
)

// TestHttpRequestURL_ConcurrentParamIteration guards the race the detector
// reported when several passive modules ran in parallel over one item: URL()
// handed every caller the same cached *urlutil.URL, and OrderedParams.Iterate
// (and URL.Clone, which iterates) writes the ordered map's internal iteration
// flag, so two read-only callers raced. Run under -race.
func TestHttpRequestURL_ConcurrentParamIteration(t *testing.T) {
	raw := []byte("GET /search?q=1&redirect=https%3A%2F%2Fx.test&token=abc&q=2 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := NewHttpRequestWithService(NewServiceSecure("example.com", 443, true), raw)
	rr := NewHttpRequestResponse(req, nil)

	const goroutines = 16
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan string, goroutines*3)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			for n := 0; n < 50; n++ {
				u, err := rr.URL()
				if err != nil || u == nil || u.Params == nil {
					errs <- "URL() returned no params"
					return
				}
				keys := 0
				u.Params.Iterate(func(string, []string) bool {
					keys++
					return true
				})
				if keys != 3 {
					errs <- "unexpected param count"
					return
				}
				// Cloning (what BuildRetryableRequest does) iterates too.
				c := u.Clone()
				// A caller mutating its own copy must not leak into others.
				if i%2 == 0 {
					u.Params.Set("q", "mutated")
					c.Params.Set("q", "mutated")
				}
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}

	u, err := req.URL()
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Params.GetAll("q"); len(got) != 2 || got[0] != "1" || got[1] != "2" {
		t.Fatalf("q params = %v, want [1 2] (a caller's mutation leaked into the cache)", got)
	}
	if got := u.String(); got != "https://example.com/search?q=1&q=2&redirect=https%3A%2F%2Fx.test&token=abc" {
		t.Fatalf("URL().String() = %q", got)
	}
}
