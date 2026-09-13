package input_behavior_probe

import (
	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
)

// probeDebugParams appends debug/admin parameter name×value combinations
// and checks each response against the baseline for behavior changes.
func probeDebugParams(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	baseline *detectionBaseline,
) []*output.ResultEvent {
	urlx, err := ctx.URL()
	if err != nil {
		return nil
	}
	urlStr := urlx.String()
	var results []*output.ResultEvent

	for _, name := range debugParamNames {
		for _, value := range debugParamValues {
			raw, err := httpmsg.AppendURLParameter(ctx.Request().Raw(), name, value)
			if err != nil {
				continue
			}

			// raw is well-formed raw, so wrap directly instead of re-parsing on this hot path.
			req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())

			resp, _, err := httpClient.Execute(req, probeOptions(false))
			if err != nil {
				if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
					return results
				}
				continue
			}

			change := detectChange(baseline, resp.Body().String(), resp.Response().StatusCode)
			if confirmChange(ctx, httpClient, baseline, raw, change) {
				results = append(results, buildProbeResult(
					urlStr, raw, resp.FullResponseString(),
					name, "debug_param", name+"="+value, change,
				))
			}
			resp.Close()
		}
	}

	return results
}
