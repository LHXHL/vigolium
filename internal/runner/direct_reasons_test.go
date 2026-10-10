package runner

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
)

func TestApplyDirectPhaseReason(t *testing.T) {
	tally := database.TargetTally{Requested: 1, Admitted: 1, Reached: 1}
	clean := DirectScanCompletion(core.ExecutionReport{Responded: 1}, true, false, nil, tally)
	if clean.Completeness != database.CompletenessComplete {
		t.Fatalf("baseline completion = %+v, want complete", clean)
	}

	if got := ApplyDirectPhaseReason(clean, ""); got.Completeness != database.CompletenessComplete {
		t.Errorf("empty reason changed the completion: %+v", got)
	}

	got := ApplyDirectPhaseReason(clean, database.ReasonOASTUnavailable)
	if got.Completeness != database.CompletenessPartial || got.StopReason != database.ReasonOASTUnavailable {
		t.Errorf("oast_unavailable: completeness=%q stop=%q, want partial/oast_unavailable", got.Completeness, got.StopReason)
	}
	var da *database.PhaseOutcome
	for i := range got.Phases {
		if got.Phases[i].Phase == string(PhaseDynamicAssessment) {
			if da != nil {
				t.Fatal("dynamic-assessment outcome duplicated instead of merged")
			}
			da = &got.Phases[i]
		}
	}
	if da == nil || da.State != database.PhasePartial {
		t.Fatalf("dynamic-assessment outcome = %+v, want partial", da)
	}

	// A scan something else already stopped keeps that stop reason.
	cancelled := DirectScanCompletion(core.ExecutionReport{Responded: 1}, true, true, nil, tally)
	if got := ApplyDirectPhaseReason(cancelled, database.ReasonScanBudget); got.StopReason != database.ReasonCancelled {
		t.Errorf("stop reason = %q, want cancelled kept", got.StopReason)
	}
}
