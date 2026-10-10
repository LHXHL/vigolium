package server

import "testing"

// The REST request budget reaches the options (overriding scanning_pace), the
// config value fills an absent one, and a negative one is a client error.
func TestResolveRunScanRequest_RequestBudget(t *testing.T) {
	target := []string{"http://example.test/"}
	settings := testProfilesSettings(t)
	settings.ScanningPace.MaxRequests = 900
	settings.ScanningPace.MaxRequestsPerHost = 90
	opts, _, err := ResolveRunScanRequest(settings, 0, RunScanRequest{Targets: target, MaxRequests: 50}, "p")
	if err != nil {
		t.Fatal(err)
	}
	if opts.MaxRequests != 50 || opts.MaxRequestsPerHost != 90 {
		t.Fatalf("budget = %d/%d, want 50 (request) / 90 (config)", opts.MaxRequests, opts.MaxRequestsPerHost)
	}

	recOpts, _, err := resolveScanAllRecordsOptions(testProfilesSettings(t), 0, ScanAllRecordsRequest{MaxRequestsPerHost: 7}, "p")
	if err != nil {
		t.Fatal(err)
	}
	if recOpts.MaxRequestsPerHost != 7 {
		t.Fatalf("records route per-host budget = %d, want 7", recOpts.MaxRequestsPerHost)
	}

	if err := validateRunScanRequest(RunScanRequest{Targets: target, MaxRequests: -1}); err == nil {
		t.Fatal("a negative max_requests must be rejected")
	}
	if err := validateScanAllRecordsRequest(ScanAllRecordsRequest{MaxRequestsPerHost: -1}); err == nil {
		t.Fatal("a negative max_requests_per_host must be rejected")
	}
}
