package claudecost

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/olium"
)

// The agent's default model must have a row of its own. Without one it falls
// through to defaultPricing (the Opus 4.x tier) and every audit run is billed
// at roughly 3x its real cost — silently, since PricingFor cannot fail. Pinned
// to the live constant so the next generation bump fails here rather than in
// someone's cost report.
func TestPricingCoversDefaultModel(t *testing.T) {
	if got := PricingFor(olium.DefaultAnthropicModel); got.Model == defaultPricing.Model {
		t.Errorf("PricingFor(%q) fell through to the default tier (%.2f/%.2f per MTok); add a row to pricingTable",
			olium.DefaultAnthropicModel, got.InputUSDPerMTok, got.OutputUSDPerMTok)
	}
}
