package runner

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/oast"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// oastUncorrelatedMessage is the one-line notice for a fixed oast_url without
// {nonce}: blind checks still plant it, but every probe plants the same URL.
const oastUncorrelatedMessage = "oast.mode: fixed-uncorrelated — oast_url has no " + oast.NoncePlaceholder +
	" placeholder, so out-of-band callbacks cannot be attributed to the probe that planted them. " +
	"Use a template such as https://" + oast.NoncePlaceholder + ".cb.example.com and `vigolium oast ingest` the endpoint's log"

// reportOASTMode says once, at the start of dynamic assessment, when the OAST
// service runs with a fixed URL that cannot correlate callbacks: a Warn log, an
// error event and one stderr line. The scan is not marked partial: the blind
// probes still run, only their attribution is lost.
func (r *Runner) reportOASTMode(svc *oast.Service) {
	if svc.Mode() != oast.ModeFixedUncorrelated {
		return
	}
	zap.L().Warn("OAST: fixed URL without {nonce}; callbacks cannot be correlated",
		zap.String("oast.mode", oast.ModeFixedUncorrelated), zap.String("oast_url", svc.ServerURL()))
	scanevents.Emit(scanevents.Event{
		Type:    scanevents.TypeError,
		Phase:   string(PhaseDynamicAssessment),
		Message: oastUncorrelatedMessage,
		Detail:  "oast.mode=" + oast.ModeFixedUncorrelated,
	})
	if r.scanLogger != nil {
		r.scanLogger.Warn("dynamic-assessment", oastUncorrelatedMessage)
	}
	r.printPhaseDetail(fmt.Sprintf("%s %s", terminal.Yellow(terminal.SymbolWarning), oastUncorrelatedMessage))
}
