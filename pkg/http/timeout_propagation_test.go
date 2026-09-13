package http

import (
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/types"
)

// TestRequesterHonorsConfiguredTimeout pins the effective request deadline.
//
// retryablehttp.NewWithHTTPClient hands its Options to NewClient, which overwrites
// the supplied client's Timeout whenever Options.Timeout > 0. DefaultOptionsSpraying
// carries 30s, so the Timeout set on the http.Client was silently discarded and
// --timeout did nothing on this path: a short value was ignored and a long one was
// truncated, both to 30s. These are constructor assertions — no wall-clock waiting.
func TestRequesterHonorsConfiguredTimeout(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured time.Duration
		want       time.Duration
	}{
		{"short", 5 * time.Second, 5 * time.Second},
		{"cli default", 15 * time.Second, 15 * time.Second},
		{"long", 90 * time.Second, 90 * time.Second},
		// Unset keeps the dependency default rather than becoming an unbounded
		// client: http.Client{Timeout: 0} never gives up.
		{"unset", 0, defaultRequestTimeout},
		{"negative", -1 * time.Second, defaultRequestTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := types.DefaultOptions()
			opts.Timeout = tc.configured
			r := newTestRequesterWithOpts(t, opts)

			if got := r.client.HTTPClient.Timeout; got != tc.want {
				t.Errorf("redirect client timeout = %v, want %v", got, tc.want)
			}
			if got := r.clientNoRedir.HTTPClient.Timeout; got != tc.want {
				t.Errorf("no-redirect client timeout = %v, want %v", got, tc.want)
			}

			// An anonymous view must not silently run on a different deadline.
			view, err := r.CloneWithoutCredentials()
			if err != nil {
				t.Fatalf("CloneWithoutCredentials: %v", err)
			}
			if got := view.client.HTTPClient.Timeout; got != tc.want {
				t.Errorf("view client timeout = %v, want %v", got, tc.want)
			}
		})
	}
}
