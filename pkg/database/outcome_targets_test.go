package database

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// The field is additive on a jsonb column: an outcome without it must encode
// exactly as before, and one with it must round-trip.
func TestPhaseOutcomeTargetsJSON(t *testing.T) {
	t.Parallel()
	plain, err := json.Marshal(PhaseOutcome{Phase: "dast", State: PhaseCompleted})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), "targets") {
		t.Errorf("outcome without a tally encodes a targets key: %s", plain)
	}

	in := PhaseOutcome{Phase: "preflight", State: PhasePartial, Reasons: []string{"targets_out_of_scope"},
		Targets: &TargetTally{Requested: 2, Admitted: 1, Reached: 1,
			Rejected: []TargetIssue{{Target: "https://x.test", Code: "scope.host.include"}}}}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"targets":{"requested":2,"admitted":1,"reached":1,"rejected":[{"target":"https://x.test","code":"scope.host.include"}]}`) {
		t.Errorf("unexpected encoding: %s", raw)
	}
	var out PhaseOutcome
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.Targets == nil || out.Targets.Admitted != 1 || len(out.Targets.Rejected) != 1 {
		t.Errorf("round-trip lost the tally: %+v", out.Targets)
	}

	// Rows written before the field existed decode with a nil tally.
	var old PhaseOutcome
	if err := json.Unmarshal([]byte(`{"phase":"dast","state":"completed","duration_ms":5}`), &old); err != nil {
		t.Fatal(err)
	}
	if old.Targets != nil {
		t.Errorf("old row decoded a tally: %+v", old.Targets)
	}
}

func TestTargetTallyCapAndMerge(t *testing.T) {
	t.Parallel()
	var a TargetTally
	for i := 0; i < TargetIssueCap+5; i++ {
		a.AddRejected(TargetIssue{Target: fmt.Sprintf("t%d", i), Code: "scope.host.include"})
	}
	if len(a.Rejected) != TargetIssueCap {
		t.Errorf("Rejected len = %d, want %d", len(a.Rejected), TargetIssueCap)
	}
	a.AddUnreachable(TargetIssue{Target: "u", Code: "refused", Detail: strings.Repeat("x", 2*OutcomeMessageMax)})
	if len(a.Unreachable[0].Detail) > OutcomeMessageMax {
		t.Errorf("detail not truncated: %d bytes", len(a.Unreachable[0].Detail))
	}

	o := PhaseOutcome{Phase: "preflight"}
	o.Merge(PhaseOutcome{Phase: "preflight", Targets: &TargetTally{Requested: 2, Admitted: 1, Reached: 1,
		Unreachable: []TargetIssue{{Target: "a", Code: "dns"}}}})
	o.Merge(PhaseOutcome{Phase: "preflight", Targets: &TargetTally{Requested: 1, Admitted: 1,
		Unreachable: []TargetIssue{{Target: "b", Code: "timeout"}}}})
	o.Merge(PhaseOutcome{Phase: "preflight"})
	got := o.Targets
	if got == nil || got.Requested != 3 || got.Admitted != 2 || got.Reached != 1 || len(got.Unreachable) != 2 {
		t.Errorf("merged tally = %+v", got)
	}
}
