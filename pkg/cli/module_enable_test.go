package cli

import (
	"errors"
	"testing"
)

// A search that matches no module used to print a warning to stdout and exit
// 0, so a typo'd ID in a setup script read as a successful enable.
func TestModuleEnableDisableNoMatchIsUsageError(t *testing.T) {
	const search = "zz-no-such-module-zz"
	for name, run := range map[string]func() error{
		"enable":  func() error { return runModuleEnable(nil, []string{search}) },
		"disable": func() error { return runModuleDisable(nil, []string{search}) },
	} {
		err := run()
		var usage usageError
		if !errors.As(err, &usage) {
			t.Errorf("module %s with no match: err = %v, want a usage error", name, err)
			continue
		}
		if got := classifyExitCode(err); got != ExitUsageError {
			t.Errorf("module %s with no match: exit = %d, want %d", name, got, ExitUsageError)
		}
	}
}
