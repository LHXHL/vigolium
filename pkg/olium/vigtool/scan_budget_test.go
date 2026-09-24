package vigtool

import (
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// TestScanToolsDeclareTheirBudget pins that every scan-launching tool tells
// the engine how long it needs (tool.LongRunning). Without it the engine's
// 5-minute default cancels the scan mid-phase.
func TestScanToolsDeclareTheirBudget(t *testing.T) {
	ctx := &ScanContext{}
	cases := []struct {
		name string
		tl   tool.Tool
		want time.Duration
	}{
		{"run_native_scan", NewRunScanTool(ctx), 30 * time.Minute},
		{"run_module", NewRunModuleTool(ctx), 15 * time.Minute},
		{"run_extension", NewRunExtensionTool(ctx), 15 * time.Minute},
	}
	for _, c := range cases {
		lr, ok := c.tl.(tool.LongRunning)
		if !ok {
			t.Errorf("%s does not implement tool.LongRunning", c.name)
			continue
		}
		if got := lr.MaxDuration(); got != c.want {
			t.Errorf("%s MaxDuration = %s, want %s", c.name, got, c.want)
		}
	}
}
