package http

import (
	"sync/atomic"

	"github.com/pkg/errors"
)

// ErrNetworkDisabled is what every request on an offline requester fails
// with (wrapped, so the message can say how to turn the network on).
var ErrNetworkDisabled = errors.New("network disabled")

// networkDisabledError carries an offline requester's message and unwraps to
// ErrNetworkDisabled.
type networkDisabledError struct{ msg string }

func (e *networkDisabledError) Error() string { return e.msg }
func (e *networkDisabledError) Unwrap() error { return ErrNetworkDisabled }

// NewOfflineRequester returns a Requester that refuses every request before it
// is admitted anywhere: Execute fails with an error wrapping
// ErrNetworkDisabled whose message is msg (empty: "network disabled"), and the
// refusal is counted (RequestsRefused). Nothing is dialed, rate-limited or
// gated, so it needs no network.Init and no Services.
//
// It is the transport of `vigolium ext eval --record-uuid`, which runs an
// extension against a stored record without letting it reach the target: a
// module that calls Execute gets the error instead of a response, and the
// count says how many calls the extension tried to make.
func NewOfflineRequester(msg string) *Requester {
	if msg == "" {
		msg = ErrNetworkDisabled.Error()
	}
	return &Requester{
		offline:       &networkDisabledError{msg: msg},
		refused:       &atomic.Int64{},
		sent:          &atomic.Int64{},
		carried:       &carriedSessionStore{},
		blockNotifier: &blockNotifier{seen: make(map[string]struct{})},
		respObserver:  &responseObserver{},
		edgePacer:     &edgePacer{},
		poolStats:     newPoolStats(),
	}
}

// RequestsRefused returns how many requests an offline requester (and every
// clone of it) refused. Zero for a normal requester and a nil one.
func (r *Requester) RequestsRefused() int64 {
	if r == nil || r.refused == nil {
		return 0
	}
	return r.refused.Load()
}
