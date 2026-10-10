package response_header_injection

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/output"
)

// metaTechnique is the ResultEvent.Metadata key naming the payload technique
// (payload.name) that produced a result.
const metaTechnique = "technique"

func resultMetadata(technique string) map[string]any {
	return map[string]any{
		output.MetaSignal: output.SignalInband,
		metaTechnique:     technique,
	}
}

// ConfirmsResultByBodyDifferential opts results into the executor's
// body-differential re-confirmation, except those of the Set-Cookie
// techniques: the differential strips Set-Cookie lines as per-request noise,
// so an injected cookie never counts as introduced content and a real finding
// would be dropped. The X-Injected header and body-break techniques leave the
// canary on a line the differential keeps.
func (m *Module) ConfirmsResultByBodyDifferential(result *output.ResultEvent) bool {
	if result.Signal() != output.SignalInband {
		return false
	}
	technique, _ := result.Metadata[metaTechnique].(string)
	return technique != "" && !strings.Contains(technique, "setcookie")
}
