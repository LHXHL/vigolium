package xxe_generic

import "github.com/vigolium/vigolium/pkg/output"

// ConfirmsResultByBodyDifferential opts the in-band results (a file or entity
// marker in the payload response) into the executor's body-differential
// re-confirmation. The blind leg's proof is an OAST callback, which a replay
// cannot show, so a result carrying any other signal is left alone.
func (m *Module) ConfirmsResultByBodyDifferential(result *output.ResultEvent) bool {
	return result.Signal() == output.SignalInband
}
