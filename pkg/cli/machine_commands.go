package cli

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
