package cli

import (
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
)

// handleConfirmation is the cli-package binding of the shared confirmation gate.
// The implementation and the reasoning behind it live in
// pkg/cli/internal/clicommon/confirm.go, which configcmd also uses; this wrapper
// exists only to supply --force from the package global so call sites stay short.
//
//	if done, err := handleConfirmation("deleting 41 findings in project X"); done {
//	    return err
//	}
func handleConfirmation(action string) (done bool, err error) {
	return clicommon.HandleConfirmation(action, globalForce)
}

// errConfirmationRequired is re-exported for classifyExitCode, which maps a
// refused non-interactive mutation to the usage-error exit code.
var errConfirmationRequired = clicommon.ErrConfirmationRequired
