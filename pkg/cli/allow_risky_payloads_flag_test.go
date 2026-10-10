package cli

import (
	"testing"

	"github.com/spf13/pflag"
)

// TestAllowRiskyPayloadsFlag checks the tri-state binding: absent leaves
// scanOpts.AllowRiskyPayloads nil (config decides), a bare flag sets true, and
// an explicit =false is recorded so it can override a config true.
func TestAllowRiskyPayloadsFlag(t *testing.T) {
	saved := scanOpts.AllowRiskyPayloads
	t.Cleanup(func() { scanOpts.AllowRiskyPayloads = saved })

	cases := []struct {
		args []string
		want *bool
	}{
		{nil, nil},
		{[]string{"--allow-risky-payloads"}, ptrBool(true)},
		{[]string{"--allow-risky-payloads=false"}, ptrBool(false)},
	}
	for _, c := range cases {
		scanOpts.AllowRiskyPayloads = nil
		fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
		registerAllowRiskyPayloadsFlag(fs)
		if err := fs.Parse(c.args); err != nil {
			t.Fatalf("%v: parse: %v", c.args, err)
		}
		got := scanOpts.AllowRiskyPayloads
		if (got == nil) != (c.want == nil) || (got != nil && *got != *c.want) {
			t.Errorf("%v: AllowRiskyPayloads = %v, want %v", c.args, got, c.want)
		}
	}

	for _, name := range []string{"scan", "run", "scan-url", "scan-request"} {
		cmd, _, err := rootCmd.Find([]string{name})
		if err != nil || cmd.Flags().Lookup("allow-risky-payloads") == nil {
			t.Errorf("%s: --allow-risky-payloads not registered (err=%v)", name, err)
		}
	}
}

func ptrBool(v bool) *bool { return &v }
