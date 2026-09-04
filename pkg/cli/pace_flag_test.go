package cli

import (
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

func newTestKnob(t *testing.T) (*paceKnob, *int) {
	t.Helper()
	var dest int
	return newPaceKnob("rate-limit", &dest, 100), &dest
}

func TestPaceKnobBareValueSetsGlobal(t *testing.T) {
	k, dest := newTestKnob(t)
	if err := k.Set("50"); err != nil {
		t.Fatal(err)
	}
	if *dest != 50 {
		t.Errorf("global = %d, want 50", *dest)
	}
	if len(k.perPhase) != 0 {
		t.Error("bare value created a phase override")
	}
	if !k.globalChanged() {
		t.Error("bare value did not mark the global as set")
	}
}

func TestPaceKnobRejectsNegative(t *testing.T) {
	// A negative pace is a typo, not "unlimited". Reading it as unlimited turns a
	// caller asking for restraint into one explicitly asking for none — the
	// fail-open direction on a safety knob.
	k, _ := newTestKnob(t)
	err := k.Set("-5")
	if err == nil {
		t.Fatal("--rate-limit -5 accepted")
	}
	if !strings.Contains(err.Error(), ">= 0") {
		t.Errorf("error does not explain the rule: %v", err)
	}
}

func TestPaceKnobZeroIsExplicitUnlimited(t *testing.T) {
	k, dest := newTestKnob(t)
	if err := k.Set("0"); err != nil {
		t.Fatalf("--rate-limit 0 rejected: %v", err)
	}
	if *dest != 0 {
		t.Errorf("global = %d, want 0", *dest)
	}
}

func TestPaceKnobPhaseQualifier(t *testing.T) {
	k, dest := newTestKnob(t)
	if err := k.Set("known-issue-scan=20"); err != nil {
		t.Fatal(err)
	}
	if got, ok := k.forPhase("known-issue-scan"); !ok || got != 20 {
		t.Errorf("forPhase = (%d,%v), want (20,true)", got, ok)
	}
	// A qualified value must NOT move the invocation-wide dial: the whole point
	// is capping one phase without capping its siblings.
	if *dest != 100 {
		t.Errorf("global = %d, want the untouched default 100", *dest)
	}
	// …and must not read as an explicit global either. pflag marks the flag
	// Changed for a qualified form too, which is why the explicitness gates ask
	// globalChanged instead: reading it as global skipped the --strategy lite
	// ceiling and made the runner refuse the per-phase value just written.
	if k.globalChanged() {
		t.Error("a phase-qualified value marked the global as explicitly set")
	}
}

func TestPaceKnobRoundTripsThroughSliceValue(t *testing.T) {
	// childScanArgs re-emits parent flags to -P child processes and treats a
	// SliceValue's GetSlice as the re-passable form. Without it String() renders
	// only the global int, so every phase cap silently vanished in the fan-out.
	k, _ := newTestKnob(t)
	for _, v := range []string{"50", "known-issue-scan=20", "discovery=5"} {
		if err := k.Set(v); err != nil {
			t.Fatal(err)
		}
	}
	got := k.GetSlice()
	want := []string{"50", "discovery=5", "known-issue-scan=20"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("GetSlice = %v, want %v", got, want)
	}

	// Replaying that slice into a fresh knob must reproduce the same state.
	replayed, dest2 := newTestKnob(t)
	if err := replayed.Replace(got); err != nil {
		t.Fatal(err)
	}
	if *dest2 != 50 {
		t.Errorf("replayed global = %d, want 50", *dest2)
	}
	if v, _ := replayed.forPhase("known-issue-scan"); v != 20 {
		t.Errorf("replayed phase = %d, want 20", v)
	}
}

func TestPaceKnobOmitsUntypedGlobalFromSlice(t *testing.T) {
	// An untyped global is a default, not an instruction. Emitting it to a child
	// would overwrite whatever that child's own config resolves to.
	k, _ := newTestKnob(t)
	if err := k.Set("discovery=5"); err != nil {
		t.Fatal(err)
	}
	if got := k.GetSlice(); strings.Join(got, ",") != "discovery=5" {
		t.Errorf("GetSlice = %v, want only the qualified value", got)
	}
}

func TestPaceKnobPhaseZeroIsHonored(t *testing.T) {
	// 0 means unlimited, which the flag's own error text documents. Packing the
	// three knobs into a struct lost the "was set" bit and made the writer
	// re-derive it with `> 0`, silently dropping exactly this.
	k, _ := newTestKnob(t)
	if err := k.Set("known-issue-scan=0"); err != nil {
		t.Fatal(err)
	}
	v, ok := k.forPhase("known-issue-scan")
	if !ok || v != 0 {
		t.Errorf("forPhase = (%d,%v), want (0,true)", v, ok)
	}
}

func TestPaceKnobPhaseAliasResolves(t *testing.T) {
	// The aliases --only/--skip accept must work here too; a qualifier valid on
	// one flag and unknown on another is exactly the surface a driver gets wrong.
	k, _ := newTestKnob(t)
	if err := k.Set("kis=7"); err != nil {
		t.Fatal(err)
	}
	if got, ok := k.forPhase("known-issue-scan"); !ok || got != 7 {
		t.Errorf("alias kis did not resolve: (%d,%v)", got, ok)
	}
}

func TestPaceKnobRejectsUnknownPhase(t *testing.T) {
	// A typo'd qualifier that parsed would be a cap the operator believes is in
	// force and is not.
	k, _ := newTestKnob(t)
	err := k.Set("discovry=10")
	if err == nil {
		t.Fatal("unknown phase accepted")
	}
	if !strings.Contains(err.Error(), "discovry") {
		t.Errorf("error does not quote what was typed: %v", err)
	}
}

func TestPaceKnobMixesGlobalAndPhase(t *testing.T) {
	k, dest := newTestKnob(t)
	for _, v := range []string{"50", "known-issue-scan=20"} {
		if err := k.Set(v); err != nil {
			t.Fatalf("Set(%q): %v", v, err)
		}
	}
	if *dest != 50 {
		t.Errorf("global = %d, want 50", *dest)
	}
	if got, _ := k.forPhase("known-issue-scan"); got != 20 {
		t.Errorf("phase = %d, want 20", got)
	}
}

func TestPaceKnobSeedsDefaultForHelp(t *testing.T) {
	// pflag reads String() at registration to build DefValue, and registration
	// happens inside other files' init funcs, which Go may run before this one's.
	// A knob that seeded later would print "0" in --help.
	var dest int
	k := newPaceKnob("concurrency", &dest, 40)
	if k.String() != "40" {
		t.Errorf("String() = %q before any Set, want the seeded default 40", k.String())
	}
}

func TestPaceKnobRegistersOnMultipleFlagSets(t *testing.T) {
	// Five commands register these at init and only one ever executes; sharing
	// one instance is what makes registration order irrelevant.
	var dest int
	k := newPaceKnob("rate-limit", &dest, 100)
	for _, name := range []string{"a", "b"} {
		fs := pflag.NewFlagSet(name, pflag.ContinueOnError)
		fs.Var(k, "rate-limit", "")
	}
	if err := k.Set("known-issue-scan=9"); err != nil {
		t.Fatal(err)
	}
	if got, ok := k.forPhase("known-issue-scan"); !ok || got != 9 {
		t.Errorf("shared instance lost its value: (%d,%v)", got, ok)
	}
}
