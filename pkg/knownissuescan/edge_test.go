package knownissuescan

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPreflightDropsBlockedHosts(t *testing.T) {
	// The failure this exists to remove: an unknown target opened at up to 100
	// rps with no way to slow down, the edge starts filtering, and the phase
	// returns a thin surface indistinguishable from a clean target. A host that
	// is already blocking gets dropped rather than scanned.
	targets := []string{
		"https://blocked.example/",
		"https://blocked.example/admin",
		"https://open.example/",
	}
	probe := func(_ context.Context, rawURL string) (bool, error) {
		return strings.Contains(rawURL, "blocked.example"), nil
	}
	keep, blocked := preflightHosts(context.Background(), targets, probe)
	if len(blocked) != 1 || blocked[0] != "blocked.example" {
		t.Fatalf("blocked = %v, want [blocked.example]", blocked)
	}
	for _, k := range keep {
		if strings.Contains(k, "blocked.example") {
			t.Errorf("blocked host survived: %s", k)
		}
	}
	if len(keep) != 1 {
		t.Errorf("keep = %v, want only the open host", keep)
	}
}

func TestPreflightProbesOncePerHost(t *testing.T) {
	// One probe per host, not per target: a block is a property of the edge, not
	// of the path, and an enriched list carries many paths per host.
	targets := []string{"https://a.example/1", "https://a.example/2", "https://a.example/3"}
	calls := 0
	probe := func(context.Context, string) (bool, error) {
		calls++
		return false, nil
	}
	preflightHosts(context.Background(), targets, probe)
	if calls != 1 {
		t.Errorf("probe calls = %d, want 1", calls)
	}
}

func TestPreflightProbeErrorKeepsHost(t *testing.T) {
	// A probe error is a transport failure, not a block. Scanning is still the
	// right call — nuclei retries on its own.
	targets := []string{"https://a.example/"}
	probe := func(context.Context, string) (bool, error) {
		return false, errors.New("dial timeout")
	}
	keep, blocked := preflightHosts(context.Background(), targets, probe)
	if len(blocked) != 0 {
		t.Errorf("blocked = %v, want none", blocked)
	}
	if len(keep) != 1 {
		t.Errorf("keep = %v, want the host retained", keep)
	}
}

func TestPreflightWithoutProbeIsAPassthrough(t *testing.T) {
	// With no hooks the phase behaves exactly as it did before.
	targets := []string{"https://a.example/"}
	keep, blocked := preflightHosts(context.Background(), targets, nil)
	if len(keep) != 1 || len(blocked) != 0 {
		t.Errorf("keep=%v blocked=%v, want the input unchanged", keep, blocked)
	}
}

func TestPacedForNarrowsToTheMostConstrainedHost(t *testing.T) {
	// One invocation drives one nuclei engine, so the phase can only open as wide
	// as its most constrained host allows without bursting that host.
	targets := []string{"https://a.example/", "https://b.example/"}
	read := func(host string) (int, int) {
		if host == "a.example" {
			return 40, 40 // untouched
		}
		return 10, 40 // paced down to a quarter
	}
	conc, rate := pacedFor(targets, read, 40, 100)
	if conc != 10 {
		t.Errorf("concurrency = %d, want 10 (a quarter of 40)", conc)
	}
	if rate != 25 {
		t.Errorf("rate = %d, want 25 (a quarter of 100)", rate)
	}
}

func TestPacedForLeavesUnpacedHostsAlone(t *testing.T) {
	targets := []string{"https://a.example/"}
	read := func(string) (int, int) { return 40, 40 }
	conc, rate := pacedFor(targets, read, 40, 100)
	if conc != 40 || rate != 100 {
		t.Errorf("pacedFor = (%d,%d), want (40,100) unchanged", conc, rate)
	}
}

func TestPacedForNeverGoesBelowOne(t *testing.T) {
	// A ratio that rounds to zero would stop the phase entirely rather than slow
	// it down.
	targets := []string{"https://a.example/"}
	read := func(string) (int, int) { return 1, 100 }
	conc, rate := pacedFor(targets, read, 2, 3)
	if conc < 1 || rate < 1 {
		t.Errorf("pacedFor = (%d,%d), want both >= 1", conc, rate)
	}
}

func TestPacedForWithoutReaderIsAPassthrough(t *testing.T) {
	conc, rate := pacedFor([]string{"https://a/"}, nil, 40, 100)
	if conc != 40 || rate != 100 {
		t.Errorf("pacedFor = (%d,%d), want the inputs unchanged", conc, rate)
	}
}

func TestGroupTargetsByHostPicksShortestRepresentative(t *testing.T) {
	// The shortest target is the closest thing to a host root in an enriched
	// list: the cheapest to probe, and the least likely to be a path the edge
	// treats specially.
	got := groupTargetsByHost([]string{
		"https://a.example/deep/nested/path",
		"https://a.example/",
	})
	if got["a.example"] != "https://a.example/" {
		t.Errorf("representative = %q, want the shortest", got["a.example"])
	}
}

func TestUnattendedDefaultsAreConservative(t *testing.T) {
	// These are the values that apply when the operator says nothing, and they
	// are the phase's only protection in that case — nuclei does not pace itself.
	if defaultRateLimit > 50 {
		t.Errorf("defaultRateLimit = %d; an unattended phase should not open wide", defaultRateLimit)
	}
	if defaultHostConcurrency > 20 {
		t.Errorf("defaultHostConcurrency = %d; too wide for an unattended phase", defaultHostConcurrency)
	}
}
