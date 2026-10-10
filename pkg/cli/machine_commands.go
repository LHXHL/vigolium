package cli

import "github.com/spf13/cobra"

// MachineContractCommands returns every runnable command path (without the
// root name; "" is the root) and the kind of -j output it declares: read,
// mutation, scan, stream or interactive.
//
// It is the machine_kinds.go table, which TestMachineContractCobraTree keeps
// equal to the runnable command tree. Exported for the runtime smoke matrix
// (test/e2e/machine_contract_e2e_test.go), which must cover every leaf and
// cannot reach the cobra tree from outside the package.
func MachineContractCommands() map[string]string {
	out := make(map[string]string, len(machineKinds))
	for path, kind := range machineKinds {
		out[path] = string(kind)
	}
	return out
}

// The running command names every result document.
//
// Envelopes used to carry a hand-typed command string, which drifted: `db
// list -j` said "traffic" (it renders through the traffic view), `db ls
// --list-tables` put flags in the name, `traffic --group-by` likewise. The
// writer now stamps the path of the command Execute is actually running, so
// `command` is the cobra path on every document, whatever its builder typed.
var (
	runningCommandPath string
	runningCommandSet  bool
)

// setRunningCommand records the command Execute is running. Called from the
// root PersistentPreRunE, once flags are parsed.
func setRunningCommand(cmd *cobra.Command) {
	if cmd == nil {
		return
	}
	runningCommandPath, runningCommandSet = commandPathWithoutRoot(cmd), true
}

// delegateCommand is for a group whose bare invocation is the documented
// shorthand for one of its subcommands (`scope` = `scope view`): the output is
// that subcommand's, so the document names it, and its schema applies.
func delegateCommand(sub *cobra.Command) {
	if runningCommandSet {
		setRunningCommand(sub)
	}
}

// stampRunningCommand names env after the running command (a no-op outside
// Execute, e.g. a test that calls an emitter directly).
func stampRunningCommand(env *agentEnvelope) {
	if env != nil && runningCommandSet {
		env.Command = runningCommandPath
	}
}
