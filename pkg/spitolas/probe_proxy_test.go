package spitolas

import "testing"

// TestSetDefaultProbeProxy pins the default-proxy contract browser
// confirmations rely on: the scan's --proxy becomes the default, restore puts
// the previous one back, and an empty value is a no-op rather than a reset.
func TestSetDefaultProbeProxy(t *testing.T) {
	if got := DefaultProbeProxy(); got != "" {
		t.Fatalf("initial default = %q, want empty", got)
	}

	restoreOuter := SetDefaultProbeProxy("http://127.0.0.1:8080")
	if got := DefaultProbeProxy(); got != "http://127.0.0.1:8080" {
		t.Fatalf("default = %q, want the installed proxy", got)
	}

	// Empty does not clear an installed default.
	SetDefaultProbeProxy("")()
	if got := DefaultProbeProxy(); got != "http://127.0.0.1:8080" {
		t.Fatalf("empty SetDefaultProbeProxy changed the default to %q", got)
	}

	restoreInner := SetDefaultProbeProxy("http://127.0.0.1:9090")
	if got := DefaultProbeProxy(); got != "http://127.0.0.1:9090" {
		t.Fatalf("nested default = %q", got)
	}
	restoreInner()
	if got := DefaultProbeProxy(); got != "http://127.0.0.1:8080" {
		t.Fatalf("after inner restore default = %q, want the outer proxy back", got)
	}
	restoreOuter()
	if got := DefaultProbeProxy(); got != "" {
		t.Fatalf("after outer restore default = %q, want empty", got)
	}
}
