package runner

import (
	"context"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/types"
)

// TestOASTMode_FixedUncorrelatedWarnsOnce: a fixed oast_url without {nonce}
// still runs the blind checks but says once that callbacks cannot be
// attributed; a {nonce} template says nothing.
func TestOASTMode_FixedUncorrelatedWarnsOnce(t *testing.T) {
	for _, tc := range []struct {
		oastURL string
		want    int
	}{
		{"https://cb.example.com/fixed", 1},
		{"https://{nonce}.cb.example.com", 0},
	} {
		buf := withEventStream(t)
		r := &Runner{
			options:  &types.Options{Silent: true},
			settings: &config.Settings{OAST: config.OASTConfig{Enabled: true, OastURL: tc.oastURL}},
		}
		infra := &phaseInfra{scanUUID: "scan-fixed"}
		svc := r.awaitOAST(context.Background(), infra)
		if svc == nil {
			t.Fatalf("%s: fixed URL service not handed to the phase", tc.oastURL)
		}
		r.reportOASTMode(svc)
		infra.Close()

		evs := eventsOfType(t, buf, scanevents.TypeError)
		if len(evs) != tc.want {
			t.Fatalf("%s: %d error events, want %d: %s", tc.oastURL, len(evs), tc.want, buf.String())
		}
		if tc.want == 1 {
			msg, _ := evs[0]["message"].(string)
			if !strings.Contains(msg, "oast.mode: fixed-uncorrelated") || evs[0]["phase"] != string(PhaseDynamicAssessment) {
				t.Errorf("event = %v", evs[0])
			}
		}
		if evs := eventsOfType(t, buf, scanevents.TypeOASTUnavailable); len(evs) != 0 {
			t.Errorf("%s: fixed URL reported as unavailable", tc.oastURL)
		}
	}
}
