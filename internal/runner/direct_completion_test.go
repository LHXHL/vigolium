package runner

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
)

func phaseByName(t *testing.T, c database.ScanCompletion, name NativePhase) database.PhaseOutcome {
	t.Helper()
	for _, p := range c.Phases {
		if p.Phase == string(name) {
			return p
		}
	}
	t.Fatalf("phase %s missing from %+v", name, c.Phases)
	return database.PhaseOutcome{}
}

func TestDirectScanCompletion(t *testing.T) {
	answered := core.ExecutionReport{Responded: 1}
	reachedTally := database.TargetTally{Requested: 1, Admitted: 1, Reached: 1}

	t.Run("clean run is complete", func(t *testing.T) {
		c := DirectScanCompletion(answered, true, false, nil, reachedTally)
		assert.Equal(t, database.CompletenessComplete, c.Completeness)
		assert.Empty(t, c.StopReason)
		pre := phaseByName(t, c, PhasePreflight)
		require.NotNil(t, pre.Targets)
		assert.Equal(t, 1, pre.Targets.Reached)
		assert.Equal(t, database.PhaseCompleted, phaseByName(t, c, PhaseDynamicAssessment).State)
		assert.Empty(t, DirectScanErrorMessage(nil, c))
	})

	t.Run("dead target stops with no_targets_reachable", func(t *testing.T) {
		tally := database.TargetTally{Requested: 1, Admitted: 1}
		tally.AddUnreachable(database.TargetIssue{Target: "http://127.0.0.1:1/", Code: "refused"})
		c := DirectScanCompletion(core.ExecutionReport{}, false, false, nil, tally)
		assert.Equal(t, database.CompletenessPartial, c.Completeness)
		assert.Equal(t, database.ReasonNoTargetsReachable, c.StopReason)
		assert.Equal(t, database.PhaseSkipped, phaseByName(t, c, PhaseDynamicAssessment).State,
			"no module had a baseline, so the assessment never ran")
		assert.Equal(t, database.PhasePartial, phaseByName(t, c, PhasePreflight).State)
		assert.NotEmpty(t, DirectScanErrorMessage(nil, c), "a run that reached nothing is a failed row")
	})

	t.Run("interrupt outranks unreachable", func(t *testing.T) {
		c := DirectScanCompletion(core.ExecutionReport{StoppedEarly: true}, false, true, nil,
			database.TargetTally{Requested: 1, Admitted: 1})
		assert.Equal(t, database.CompletenessPartial, c.Completeness)
		assert.Equal(t, database.ReasonCancelled, c.StopReason)
		da := phaseByName(t, c, PhaseDynamicAssessment)
		assert.Contains(t, da.Reasons, database.ReasonCancelled)
		assert.Contains(t, da.Reasons, database.ReasonInputIncomplete)
		assert.NotContains(t, phaseByName(t, c, PhasePreflight).Reasons, database.ReasonNoTargetsReachable)
		assert.Equal(t, "cancelled", DirectScanErrorMessage(nil, c), "matches the runner's finalizer")
	})

	t.Run("execution error fails the assessment", func(t *testing.T) {
		err := errors.New("boom")
		c := DirectScanCompletion(answered, true, false, err, reachedTally)
		assert.Equal(t, database.CompletenessPartial, c.Completeness)
		assert.Equal(t, database.ReasonError, c.StopReason)
		da := phaseByName(t, c, PhaseDynamicAssessment)
		assert.Equal(t, database.PhaseFailed, da.State)
		assert.Equal(t, "boom", da.Message)
		assert.Equal(t, "boom", DirectScanErrorMessage(err, c))
	})

	t.Run("executor shortfall is partial", func(t *testing.T) {
		c := DirectScanCompletion(core.ExecutionReport{Responded: 1, WorkersAbandoned: true, Unacked: 2}, true, false, nil, reachedTally)
		assert.Equal(t, database.CompletenessPartial, c.Completeness)
		assert.Equal(t, database.ReasonWorkersAbandoned, c.StopReason)
		assert.Equal(t, int64(2), phaseByName(t, c, PhaseDynamicAssessment).Unprocessed)
		assert.Empty(t, DirectScanErrorMessage(nil, c), "partial is not failed")
	})

	t.Run("some targets unreachable across a shared row", func(t *testing.T) {
		tally := database.TargetTally{Requested: 2, Admitted: 2, Reached: 1}
		c := DirectScanCompletion(answered, true, false, nil, tally)
		assert.Equal(t, database.CompletenessPartial, c.Completeness)
		assert.Equal(t, database.ReasonTargetsUnreachable, c.StopReason)
	})

	t.Run("scope admitted nothing (hook)", func(t *testing.T) {
		tally := database.TargetTally{Requested: 1}
		tally.AddRejected(database.TargetIssue{Target: "http://a/", Code: "scope.host.include"})
		c := DirectScanCompletion(core.ExecutionReport{}, false, false, nil, tally)
		assert.Equal(t, database.ReasonNoTargetsInScope, c.StopReason)
		assert.NotContains(t, phaseByName(t, c, PhasePreflight).Reasons, database.ReasonNoTargetsReachable,
			"nothing admitted is not the same as nothing answering")
	})

	t.Run("zero tally adds no preflight when reached", func(t *testing.T) {
		c := DirectScanCompletion(answered, true, false, nil, database.TargetTally{})
		require.Len(t, c.Phases, 1)
		assert.Equal(t, string(PhaseDynamicAssessment), c.Phases[0].Phase)
	})
}

func TestDirectTargetTally(t *testing.T) {
	ok := DirectTargetTally("http://a/", core.ExecutionReport{Responded: 1}, nil)
	assert.Equal(t, database.TargetTally{Requested: 1, Admitted: 1, Reached: 1}, ok)

	dead := DirectTargetTally("http://a/", core.ExecutionReport{},
		[]core.BaselineFailure{{Target: "http://a/", Class: "dns", Detail: "no such host"}})
	assert.Equal(t, 0, dead.Reached)
	require.Len(t, dead.Unreachable, 1)
	assert.Equal(t, "dns", dead.Unreachable[0].Code)
	assert.Equal(t, "http://a/", dead.Unreachable[0].Target)
}
