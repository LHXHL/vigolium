package modkit

import (
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
)

// FetchAssetBytes retrieves a static asset from the host a request already
// targets, returning its body only when the response is one a real asset could
// have produced.
//
// The guards are the point, and they encode non-obvious policy that every
// copy-paste of this shape has had to rediscover:
//
//   - A 200 text/html body for an asset path is the host's catch-all or SPA shell
//     answering for literally any path (or, under a gzip + bogus
//     `Content-Length: 0` transport quirk, a truncated TAIL fragment of one). Its
//     reflected text can forge a plausible secret or route-intel match, so an HTML
//     document is rejected. A missing or unknown Content-Type fails open, so a
//     real bundle served as application/octet-stream — the static-host default —
//     still comes back.
//   - resp.Close() may return the underlying buffer to a process-global pool, so
//     the body is copied before the deferred close runs. Returning the pooled
//     slice races with the next request that reuses it.
//
// Redirects and clustering are disabled: an asset probe wants the response at
// this exact path, not wherever the host would rather send it.
func FetchAssetBytes(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	path string,
	maxBytes int64,
) ([]byte, bool) {
	raw, err := httpmsg.SetPath(ctx.Request().Raw(), path)
	if err != nil {
		return nil, false
	}
	raw, _ = httpmsg.SetMethod(raw, "GET")

	// raw is internally built (well-formed), so wrap directly instead of
	// re-parsing on this hot path.
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())

	resp, _, err := httpClient.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return nil, false
	}
	defer resp.Close()

	if resp.Response() == nil || resp.Response().StatusCode != 200 || infra.IsBlockedResponse(resp) {
		return nil, false
	}
	if ClassifyContentType(resp.Response().Header.Get("Content-Type")) == ContentClassHTML {
		return nil, false
	}

	body := resp.Body().Bytes()
	if maxBytes > 0 && int64(len(body)) > maxBytes {
		body = body[:maxBytes]
	}
	out := make([]byte, len(body))
	copy(out, body)
	return out, true
}
