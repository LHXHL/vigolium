package types

// TargetVerdict is one CLI target that scope refused, and why.
type TargetVerdict struct {
	// Target is the target as the operator gave it.
	Target string `json:"target"`
	// Host is the hostname scope evaluated (no port).
	Host string `json:"host"`
	// Rule is the scope rule that refused the target: one of the
	// config.ScopeRule* constants (e.g. "scope.host.include").
	Rule string `json:"rule"`
}

// TargetAdmission is the scope verdict over a scan's CLI targets, computed before
// any request is sent (runner.AdmitTargets). It lives here rather than beside
// AdmitTargets so Options and the CLI can carry it without importing the runner.
type TargetAdmission struct {
	// Admitted are the targets scope lets through, in input order.
	Admitted []string `json:"admitted"`
	// Rejected are the targets scope refused, in input order.
	Rejected []TargetVerdict `json:"rejected,omitempty"`
}

// Requested is how many targets the admission evaluated.
func (a TargetAdmission) Requested() int { return len(a.Admitted) + len(a.Rejected) }

// NoneAdmitted reports whether targets were evaluated and every one was refused.
// An empty admission (no targets at all) is not "none admitted": there was
// nothing to refuse.
func (a TargetAdmission) NoneAdmitted() bool {
	return len(a.Admitted) == 0 && len(a.Rejected) > 0
}
