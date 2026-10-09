package text4shell_probe

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// injectionType labels the OAST payload context. It deliberately avoids the
// substrings the OAST classifier dispatches on ("header", "command", "sql",
// "xxe", "jwt", "smuggle"), so callbacks are rated by the generic DNS/HTTP rules.
const injectionType = "text4shell interpolation"

// lookupTemplates are Commons Text lookups that make the server reach the OAST
// host, with %s replaced by the callback host. Only out-of-band lookups are
// used: the script lookup that makes Text4Shell an RCE is never sent.
//
//   - dns: resolves the host (InetAddress lookup), so it works where only DNS
//     egress is allowed;
//   - url: fetches http://<host>/, a stronger HTTP signal.
var lookupTemplates = []string{
	"${dns:%s}",
	"${url:UTF-8:http://%s/}",
}

// Module implements the Text4Shell probe active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new Text4Shell probe module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeInsertionPoint,
			modkit.AllParamTypes,
		),
		rhm: dedup.LazyDefaultRHM("text4shell_probe"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint injects Commons Text lookups into one parameter.
// Findings arrive asynchronously via OAST polling callbacks.
func (m *Module) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	oast := scanCtx.OASTProv()
	if oast == nil || !oast.Enabled() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}
	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return nil, nil
	}

	if rhm := m.rhm.Get(scanCtx.DedupMgr()); rhm != nil {
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), ip.Name(), ip.BaseValue(), fmt.Sprintf("%d", ip.Type())) {
			return nil, nil
		}
	}

	requestHash := ctx.Request().ID()
	for _, tmpl := range lookupTemplates {
		// One host per template, so a callback names the lookup that fired.
		host := oast.GenerateURL(urlx.String(), ip.Name(), injectionType, ModuleID, requestHash)
		if host == "" {
			continue
		}
		payload := fmt.Sprintf(tmpl, host)
		// Record the real lookup so the finding reconstructs "${dns:...}"
		// rather than a bare callback host.
		oast.RecordPayload(host, payload)

		// BuildRequest produces well-formed raw, so wrap directly instead of
		// re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(ip.BuildRequest([]byte(payload)), ctx.Service())
		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return nil, nil
			}
			continue
		}
		resp.Close()
	}

	// Results arrive asynchronously via OAST polling callbacks.
	return nil, nil
}
