package output

// MetaSignal is the ResultEvent.Metadata key naming the kind of evidence a
// result rests on: one of SignalInband, SignalTiming or SignalOAST. Modules
// that mix legs (an in-band probe next to an OAST or time-delay probe) set it
// per result, so the executor's body-differential re-confirmation can apply to
// the in-band results only (modules.ResultDifferentialConfirmable), and
// downstream consumers can tell a replayable in-band finding from one that
// needs a callback or a timing oracle to reproduce.
const MetaSignal = "signal"

// Signal values stored under MetaSignal.
const (
	// SignalInband: the proof is in the response to the payload request (new
	// content, a header, a status change).
	SignalInband = "inband"
	// SignalTiming: the proof is a measured response delay.
	SignalTiming = "timing"
	// SignalOAST: the proof is an out-of-band callback.
	SignalOAST = "oast"
)

// Signal returns the result's MetaSignal value, or "" when unset.
func (r *ResultEvent) Signal() string {
	if r == nil || r.Metadata == nil {
		return ""
	}
	s, _ := r.Metadata[MetaSignal].(string)
	return s
}

// SetSignal records the evidence kind under MetaSignal, allocating Metadata
// when needed.
func (r *ResultEvent) SetSignal(signal string) {
	if r == nil {
		return
	}
	if r.Metadata == nil {
		r.Metadata = make(map[string]interface{}, 1)
	}
	r.Metadata[MetaSignal] = signal
}
