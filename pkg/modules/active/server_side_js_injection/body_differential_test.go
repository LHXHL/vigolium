package server_side_js_injection

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vigolium/vigolium/pkg/output"
)

// TestConfirmsResultByBodyDifferential_Signals: the timing and OAST legs are
// never body-diff re-confirmed (a replayed body cannot show a delay or a
// callback); a result marked in-band would be.
func TestConfirmsResultByBodyDifferential_Signals(t *testing.T) {
	t.Parallel()
	var _ interface {
		ConfirmsResultByBodyDifferential(*output.ResultEvent) bool
	} = (*Module)(nil)
	m := New()
	for signal, want := range map[string]bool{
		output.SignalTiming: false,
		output.SignalOAST:   false,
		output.SignalInband: true,
		"":                  false,
	} {
		r := &output.ResultEvent{}
		if signal != "" {
			r.SetSignal(signal)
		}
		assert.Equal(t, want, m.ConfirmsResultByBodyDifferential(r), signal)
	}
}
