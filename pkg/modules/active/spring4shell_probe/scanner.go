package spring4shell_probe

import (
	"fmt"
	"strconv"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// The oracle is the widely used SAFE Spring4Shell check. On a vulnerable stack
// (Spring MVC/WebFlux before 5.3.18/5.2.20 on JDK 9+) a @ModelAttribute handler
// binds the query parameter class.module.classLoader.DefaultAssertionStatus onto
// the web application's ClassLoader:
//
//   - "true" and "false" convert to boolean and bind, so the handler runs (2xx);
//   - a non-boolean value fails type conversion, so binding throws and Spring
//     answers 400 before the handler runs.
//
// A patched or non-Spring stack ignores the property path, so all three values
// return the handler's normal status. DefaultAssertionStatus only toggles
// whether assertions are enabled for classes loaded later, and the probe always
// sends "false" right after "true" to restore the JVM default. No file is
// written and no logging configuration is touched.
//
// False-positive guards (status oracles flip for many unrelated reasons):
//   - "true" AND "false" must both return the same non-error status, so a
//     server that answers 400 to any unknown parameter is rejected;
//   - a control parameter with a random name and the same non-boolean value
//     must NOT return 400, so a server that rejects that value anywhere (a
//     strict validator, a WAF keyword rule) is rejected;
//   - the true/non-boolean/false split must reproduce in a second round.
const (
	propertyPath = "class.module.classLoader.DefaultAssertionStatus"

	// typeMismatchStatus is what Spring's DefaultHandlerExceptionResolver
	// returns for a BindException / MethodArgumentNotValidException.
	typeMismatchStatus = 400

	confirmRounds = 2
)

// Module implements the Spring4Shell probe active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Spring4Shell probe module.
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
			modkit.ScanScopeRequest,
			modkit.AllParamTypes,
		),
		ds: dedup.LazyDiskSet("spring4shell_probe"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// probeResult is one request of the differential.
type probeResult struct {
	status   int
	request  string
	response string
}

// errStop aborts the probe sequence; the caller returns no finding.
var errStop = errors.New("spring4shell probe aborted")

// ScanPerRequest runs the status differential once per host+path.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return nil, nil
	}

	// Binding is per handler, so one probe per host+path is enough.
	if diskSet := m.ds.Get(scanCtx.DedupMgr()); diskSet != nil {
		if diskSet.IsSeen(utils.Sha1(urlx.Host + urlx.Path)) {
			return nil, nil
		}
	}

	ev := modkit.NewEvidenceCollector()
	var first [3]probeResult // nonbool, true, false from round 1
	for round := 1; round <= confirmRounds; round++ {
		nonBool, tru, fls, err := m.round(ctx, httpClient, propertyPath)
		if err != nil || !isBindingSplit(nonBool.status, tru.status, fls.status) {
			return nil, nil
		}
		if round == 1 {
			first = [3]probeResult{nonBool, tru, fls}
			// Control: the same non-boolean value under a random parameter
			// name. A real Spring binder ignores the unknown name, so the
			// handler runs and returns the "true" status. Any other answer
			// means the 400 is about the value, not the ClassLoader binding.
			control, err := m.send(ctx, httpClient, modkit.FreshCanary(), modkit.FreshCanary())
			if err != nil || control.status != tru.status {
				return nil, nil
			}
			ev.Add("control (random parameter, non-boolean value)", control.request, control.response)
		}
		ev.Add(fmt.Sprintf("round %d: %s=true", round, propertyPath), tru.request, tru.response)
		ev.Add(fmt.Sprintf("round %d: %s=false", round, propertyPath), fls.request, fls.response)
	}

	urlStr := urlx.String()
	return []*output.ResultEvent{{
		URL:                urlStr,
		Matched:            urlStr,
		Request:            first[0].request,
		Response:           first[0].response,
		AdditionalEvidence: ev.Entries(),
		FuzzingParameter:   propertyPath,
		RecordKind:         output.RecordKindFinding,
		EvidenceGrade:      output.EvidenceGradeDifferential,
		ExtractedResults: []string{
			"status_true=" + strconv.Itoa(first[1].status),
			"status_nonbool=" + strconv.Itoa(first[0].status),
			"status_false=" + strconv.Itoa(first[2].status),
			"rounds=" + strconv.Itoa(confirmRounds),
		},
		Info: output.Info{
			Name:        ModuleName,
			Description: ModuleDesc,
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        ModuleTags,
		},
	}}, nil
}

// round sends the non-boolean value first (the cheap negative exit: anything
// but 400 means the property is not bound), then "true", then always "false" so
// the ClassLoader's assertion status is restored whenever "true" was sent.
func (m *Module) round(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	param string,
) (nonBool, tru, fls probeResult, err error) {
	nonBool, err = m.send(ctx, httpClient, param, modkit.FreshCanary())
	if err != nil {
		return
	}
	if nonBool.status != typeMismatchStatus {
		err = errStop
		return
	}
	// "false" goes out even when the "true" request failed in transit: the
	// server may still have applied it.
	tru, err = m.send(ctx, httpClient, param, "true")
	fls, ferr := m.send(ctx, httpClient, param, "false")
	if err == nil {
		err = ferr
	}
	return
}

// isBindingSplit reports whether three statuses show a typed property bind:
// the two boolean values reach the handler alike, the non-boolean is a 400.
func isBindingSplit(nonBool, tru, fls int) bool {
	return nonBool == typeMismatchStatus &&
		tru >= 200 && tru < 400 &&
		tru == fls
}

// send appends name=value to the query string and returns the status, raw
// request and full response. Clustering is disabled because the rounds repeat
// identical requests on purpose.
func (m *Module) send(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	name, value string,
) (probeResult, error) {
	raw, err := httpmsg.AppendURLParameter(ctx.Request().Raw(), name, value)
	if err != nil {
		return probeResult{}, errStop
	}
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{NoClustering: true, NoRedirects: true})
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return probeResult{}, err
		}
		return probeResult{}, errStop
	}
	defer resp.Close()
	r := resp.Response()
	if r == nil {
		return probeResult{}, errStop
	}
	return probeResult{
		status:   r.StatusCode,
		request:  string(raw),
		response: resp.FullResponseString(),
	}, nil
}
