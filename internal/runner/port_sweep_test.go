package runner

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/vigolium/vigolium/pkg/types"
)

func TestHostAndPort(t *testing.T) {
	tests := []struct {
		in       string
		wantHost string
		wantPort string
	}{
		{"https://example.com", "example.com", "443"},
		{"http://example.com", "example.com", "80"},
		{"https://example.com:8080/path?q=1", "example.com", "8080"},
		{"example.com", "example.com", "443"},       // bare host defaults to https
		{"example.com:3000", "example.com", "3000"}, // bare host:port
		{"HTTP://Example.COM", "example.com", "80"}, // lowercased
		{"http://[::1]:8080/", "::1", "8080"},       // IPv6
		{"", "", ""},
		{"   ", "", ""},
		{"://broken", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			host, port := hostAndPort(tc.in)
			if host != tc.wantHost || port != tc.wantPort {
				t.Errorf("hostAndPort(%q) = (%q, %q), want (%q, %q)", tc.in, host, port, tc.wantHost, tc.wantPort)
			}
		})
	}
}

func TestParsePortList(t *testing.T) {
	tests := []struct {
		in   string
		want []int
	}{
		{"", nil},
		{"  ", nil},
		{"8080", []int{8080}},
		{"8080,3000,9000", []int{8080, 3000, 9000}},
		{" 8080 , 3000 ", []int{8080, 3000}},  // trims whitespace
		{"8080,8080,3000", []int{8080, 3000}}, // dedups
		{"8080,abc,3000", []int{8080, 3000}},  // drops non-numeric
		{"0,70000,-1,443", []int{443}},        // drops out-of-range
		{"foo,bar", nil},                      // nothing valid
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := parsePortList(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parsePortList(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestFormatPortList(t *testing.T) {
	if got := formatPortList([]int{8080, 3000, 9000}); got != "8080,3000,9000" {
		t.Errorf("formatPortList = %q", got)
	}
	if got := formatPortList(nil); got != "" {
		t.Errorf("formatPortList(nil) = %q, want empty", got)
	}
}

func TestCollectSweepHosts(t *testing.T) {
	r := &Runner{options: &types.Options{Targets: []string{
		"https://a.com",
		"https://a.com/other", // same host → deduped
		"http://b.com:8080",   // explicit port → recorded in existing
		"https://c.com:443",   // default https port
		"   ",                 // ignored
	}}}

	hosts, existing, truncated := r.collectSweepHosts()

	wantHosts := []string{"a.com", "b.com", "c.com"}
	if !reflect.DeepEqual(hosts, wantHosts) {
		t.Errorf("hosts = %v, want %v", hosts, wantHosts)
	}
	if truncated != 0 {
		t.Errorf("truncated = %d, want 0", truncated)
	}
	// existing must let us skip re-adding ports the user already targeted.
	for _, key := range []string{"a.com:443", "b.com:8080", "c.com:443"} {
		if _, ok := existing[key]; !ok {
			t.Errorf("existing missing %q: %v", key, existing)
		}
	}
}

func TestCollectSweepHosts_Truncates(t *testing.T) {
	targets := make([]string, 0, maxPortSweepHosts+10)
	for i := 0; i < maxPortSweepHosts+10; i++ {
		targets = append(targets, fmt.Sprintf("https://h%d.example.com", i))
	}
	r := &Runner{options: &types.Options{Targets: targets}}

	hosts, _, truncated := r.collectSweepHosts()
	if len(hosts) != maxPortSweepHosts {
		t.Errorf("len(hosts) = %d, want cap %d", len(hosts), maxPortSweepHosts)
	}
	if truncated != 10 {
		t.Errorf("truncated = %d, want 10", truncated)
	}
}

// TestDistinctSweepEndpointsSharesHostAndPort pins the reuse: the probe
// prefetch and the port sweep must read a target line the same way. A second
// URL parser here resolved a schemeless `example.com:8443` to port 443 (no
// scheme prefix means url.Parse sees Scheme="example.com"), so the prefetch
// probed a different service than the one the sweep reported.
func TestDistinctSweepEndpointsSharesHostAndPort(t *testing.T) {
	r := &Runner{options: &types.Options{Targets: []string{
		"https://a.example",
		"http://b.example",
		"c.example:8443",       // schemeless with an explicit port
		"https://a.example/x",  // same host:port as the first — deduped
		"https://d.example:80", // explicit plaintext port on an https URL
	}}}

	got := r.distinctSweepEndpoints()
	want := []sweepEndpoint{
		{host: "a.example", port: 443, https: true},
		{host: "b.example", port: 80, https: false},
		{host: "c.example", port: 8443, https: true},
		{host: "d.example", port: 80, https: false},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d endpoints %+v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("endpoint %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}
