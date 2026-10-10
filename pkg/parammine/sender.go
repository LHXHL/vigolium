package parammine

import (
	"context"

	vighttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// RequesterSender adapts a vigolium requester into a Sender. Redirects are
// recorded, not followed, and request clustering is off: every probe carries
// different canaries, and a clustered answer would be another probe's.
func RequesterSender(r *vighttp.Requester) Sender {
	return func(ctx context.Context, rr *httpmsg.HttpRequestResponse) (*httpmsg.HttpResponse, error) {
		chain, elapsed, err := r.ExecuteContext(ctx, rr, vighttp.Options{NoRedirects: true, NoClustering: true})
		if err != nil {
			return nil, err
		}
		defer chain.Close()
		headers, body := chain.HeadersBytes(), chain.BodyBytes()
		raw := make([]byte, 0, len(headers)+len(body))
		raw = append(raw, headers...)
		raw = append(raw, body...)
		return httpmsg.NewHttpResponseWithDuration(raw, elapsed), nil
	}
}
