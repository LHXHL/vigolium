package server_side_js_injection

import "github.com/vigolium/vigolium/pkg/output"

// ConfirmsResultByBodyDifferential opts in-band results into the executor's
// body-differential re-confirmation. Both legs this module runs today prove
// themselves out of band or by delay — neither shows in a replayed body — so
// their results (signal oast/timing) are never re-confirmed this way; an
// in-band leg added later is covered by marking its results inband.
func (m *Module) ConfirmsResultByBodyDifferential(result *output.ResultEvent) bool {
	return result.Signal() == output.SignalInband
}
