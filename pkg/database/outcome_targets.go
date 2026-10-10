package database

// TargetIssueCap bounds each TargetTally issue list. The tally is stored on the
// scan row and read by every listing; the counts stay exact past the cap, only
// the examples are clipped.
const TargetIssueCap = 20

// TargetTally is what happened to a scan's CLI targets before the phases ran:
// how many were asked for, how many scope admitted, how many answered, and the
// ones that did not make it. It rides on the "preflight" pseudo-phase's
// PhaseOutcome (scans.phase_outcomes, additive JSON, no migration).
type TargetTally struct {
	Requested int `json:"requested"`
	Admitted  int `json:"admitted"`
	Reached   int `json:"reached"`
	// ReachabilityChecked says every admitted target was asked whether it
	// answers (the runner's preflight GET, or the direct path's executor), so
	// Admitted-Reached is the exact unreachable count. False when the check was
	// skipped (--skip preflight, a probe-only or target-silent plan, an
	// interrupted preflight): Reached is then not a verdict.
	ReachabilityChecked bool `json:"reachability_checked,omitempty"`
	// Rejected are targets scope refused; Code is the scope rule
	// (e.g. "scope.host.include"). Capped at TargetIssueCap.
	Rejected []TargetIssue `json:"rejected,omitempty"`
	// Unreachable are admitted targets that got no HTTP answer; Code is the
	// transport error class (dns, refused, timeout, tls, reset, other). Capped
	// at TargetIssueCap.
	Unreachable []TargetIssue `json:"unreachable,omitempty"`
}

// TargetIssue is one target that was refused or did not answer.
type TargetIssue struct {
	Target string `json:"target"`
	// Code is the scope rule for a rejected target, or the transport error
	// class for an unreachable one.
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
}

// AddRejected records a scope-refused target, keeping at most TargetIssueCap.
func (t *TargetTally) AddRejected(issue TargetIssue) {
	t.Rejected = appendCappedIssue(t.Rejected, issue)
}

// AddUnreachable records a target that did not answer, keeping at most
// TargetIssueCap.
func (t *TargetTally) AddUnreachable(issue TargetIssue) {
	t.Unreachable = appendCappedIssue(t.Unreachable, issue)
}

// Merge folds another tally for the same phase into t: counts sum, issue lists
// concatenate up to the cap. See PhaseOutcome.Merge.
func (t *TargetTally) Merge(b TargetTally) {
	t.Requested += b.Requested
	t.Admitted += b.Admitted
	t.Reached += b.Reached
	t.ReachabilityChecked = t.ReachabilityChecked || b.ReachabilityChecked
	for _, issue := range b.Rejected {
		t.AddRejected(issue)
	}
	for _, issue := range b.Unreachable {
		t.AddUnreachable(issue)
	}
}

// UnreachableCount is the number of admitted targets that did not answer, and
// whether that number is known (see ReachabilityChecked). Exact past the
// Unreachable list's cap.
func (t TargetTally) UnreachableCount() (int, bool) {
	if !t.ReachabilityChecked {
		return 0, false
	}
	n := t.Admitted - t.Reached
	if n < 0 {
		n = 0
	}
	return n, true
}

func appendCappedIssue(list []TargetIssue, issue TargetIssue) []TargetIssue {
	if len(list) >= TargetIssueCap {
		return list
	}
	issue.Detail = TruncateOutcomeMessage(issue.Detail)
	return append(list, issue)
}
