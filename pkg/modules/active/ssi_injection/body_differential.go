package ssi_injection

import "github.com/vigolium/vigolium/pkg/output"

// ConfirmsResultByBodyDifferential opts the in-band echo result (the server's
// own DATE_GMT expansion between fresh tags) into the executor's
// body-differential re-confirmation. The exec directives prove themselves by
// OAST callback, which a replay cannot show.
func (m *Module) ConfirmsResultByBodyDifferential(result *output.ResultEvent) bool {
	return result.Signal() == output.SignalInband
}
