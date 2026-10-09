package sqli_boolean_blind

import "github.com/vigolium/vigolium/pkg/modules/modkit"

// The response-comparison machinery for boolean-blind detection now lives in
// pkg/modules/modkit (reconfirm.go) so the executor's re-confirmation safety net
// and other modules share one battle-tested differential. These thin aliases and
// wrappers keep this module's call sites and tests unchanged.

const (
	upperRatioBound    = modkit.UpperRatioBound
	lowerRatioBound    = modkit.LowerRatioBound
	ratioDiffTolerance = modkit.RatioDiffTolerance
)

// responseSignature aliases the shared modkit signature so existing call sites
// and tests in this package continue to compile unchanged.
type responseSignature = modkit.ResponseSignature

func newResponseSignature(statusCode int, body, reflect string) responseSignature {
	return modkit.NewResponseSignature(statusCode, body, reflect)
}

func normalizeForRatio(body, reflect string) string { return modkit.NormalizeForRatio(body, reflect) }

func tokenize(normalized string) (map[string]int, int) { return modkit.Tokenize(normalized) }

func quickRatio(a, b responseSignature) float64 { return modkit.QuickRatio(a, b) }

func ratioSimilar(a, b responseSignature) bool { return modkit.RatioSimilar(a, b) }

func isDifferent(a, b responseSignature) bool { return modkit.IsDifferent(a, b) }

func hasSubstantialBodyDifference(a, b responseSignature) bool {
	return modkit.HasSubstantialBodyDifference(a, b)
}
