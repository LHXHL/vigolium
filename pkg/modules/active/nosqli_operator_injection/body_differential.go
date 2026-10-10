package nosqli_operator_injection

import "github.com/vigolium/vigolium/pkg/output"

// metaDetection is the ResultEvent.Metadata key naming which detection path
// produced a result.
const metaDetection = "detection"

// Detection paths recorded under metaDetection.
const (
	detectionAuthBypass  = "auth_bypass"
	detectionSizeChange  = "size_change"
	detectionBooleanDiff = "boolean_diff"
	detectionTimeBased   = "time_based"
)

// ConfirmsResultByBodyDifferential opts the auth-bypass and size-change results
// into the executor's body-differential re-confirmation: both claim the
// operator payload's response carries content the clean request's does not.
//
// The time-based leg's proof is a delay, which a replayed body cannot show. The
// boolean leg is in-band but compares the always-true and always-false
// responses with each other; the always-true response can equal the clean
// baseline, so a payload-vs-baseline differential would drop real findings.
func (m *Module) ConfirmsResultByBodyDifferential(result *output.ResultEvent) bool {
	if result.Signal() != output.SignalInband {
		return false
	}
	switch result.Metadata[metaDetection] {
	case detectionAuthBypass, detectionSizeChange:
		return true
	default:
		return false
	}
}
