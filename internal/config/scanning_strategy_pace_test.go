package config

import "testing"

func TestNarrowPaceTakesTheMinimum(t *testing.T) {
	// A strategy ceiling NARROWS; choosing `lite` must not make a scan faster
	// than scanning_pace already allowed.
	if got := NarrowPace(40, 10); got != 10 {
		t.Errorf("NarrowPace(40,10) = %d, want 10", got)
	}
	if got := NarrowPace(5, 10); got != 5 {
		t.Errorf("NarrowPace(5,10) = %d, want 5 — a config gentler than the ceiling is not dragged up to it", got)
	}
}

func TestNarrowPaceZeroCeilingIsNoOp(t *testing.T) {
	// `balanced` and `deep` ship no ceiling, which is what keeps their behaviour
	// unchanged.
	if got := NarrowPace(40, 0); got != 40 {
		t.Errorf("NarrowPace(40,0) = %d, want 40", got)
	}
}

func TestNarrowPaceCeilingCapsUnlimited(t *testing.T) {
	// 0 means "no cap" for rate_limit, and a strategy ceiling is exactly the
	// thing that should turn no-cap into a cap.
	if got := NarrowPace(0, 20); got != 20 {
		t.Errorf("NarrowPace(0,20) = %d, want 20", got)
	}
}

func TestLiteStrategyShipsAPaceCeiling(t *testing.T) {
	// The whole point of V-04: `lite` and `balanced` used to open a crawl
	// identically, so a name every operator reads as "gentler on the target" was
	// gentler in module count alone.
	cfg := DefaultScanningStrategyConfig()
	lite, ok := cfg.GetStrategy("lite")
	if !ok {
		t.Fatal("lite strategy missing")
	}
	if lite.Pace == (StrategyPace{}) {
		t.Fatal("lite ships no pace ceiling")
	}

	balanced, _ := cfg.GetStrategy("balanced")
	base := DefaultScanningPaceConfig()
	liteRate := NarrowPace(base.RateLimit, lite.Pace.RateLimit)
	balancedRate := NarrowPace(base.RateLimit, balanced.Pace.RateLimit)
	if liteRate >= balancedRate {
		t.Errorf("lite rate %d is not below balanced %d", liteRate, balancedRate)
	}

	liteConc := NarrowPace(base.Concurrency, lite.Pace.Concurrency)
	balancedConc := NarrowPace(base.Concurrency, balanced.Pace.Concurrency)
	if liteConc >= balancedConc {
		t.Errorf("lite concurrency %d is not below balanced %d", liteConc, balancedConc)
	}
}

func TestBalancedAndDeepShipNoCeiling(t *testing.T) {
	// `balanced` IS the baseline (its pace is scanning_pace) and `deep` is
	// explicitly the one that opens wide; a ceiling on either would restate or
	// contradict the config.
	cfg := DefaultScanningStrategyConfig()
	for _, name := range []string{"balanced", "deep"} {
		phases, ok := cfg.GetStrategy(name)
		if !ok {
			t.Fatalf("%s missing", name)
		}
		if phases.Pace != (StrategyPace{}) {
			t.Errorf("%s ships a pace ceiling: %+v", name, phases.Pace)
		}
	}
}
