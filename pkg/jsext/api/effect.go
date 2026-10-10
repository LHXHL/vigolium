package api

// Effect classifies what a vigolium.* API function does to the world outside
// the VM. It decides what a function may do while an extension is being loaded
// or linted: ModeLoad runs a script's top-level code with every EffectPure
// handler real and every other handler replaced by a recording stub, so loading
// or linting a script can never send traffic, touch the filesystem or the
// database, run a command, or call a model.
//
// EffectUnset is the zero value on purpose: a JSFuncDef that forgets to declare
// its effect is caught by a contract test instead of silently counting as pure.
type Effect uint8

const (
	// EffectUnset is the undeclared zero value; no registered def may carry it.
	EffectUnset Effect = iota
	// EffectPure computes from its arguments (and read-only process state such
	// as config variables or the module registry) without side effects.
	EffectPure
	// EffectNetwork sends HTTP/MCP traffic, or returns an object whose methods do.
	EffectNetwork
	// EffectFS reads or writes the filesystem.
	EffectFS
	// EffectExec runs a process or changes the process environment.
	EffectExec
	// EffectDBRead reads the scan database.
	EffectDBRead
	// EffectDBWrite writes the scan database (records, findings, annotations).
	EffectDBWrite
	// EffectLLM calls a language model.
	EffectLLM
	// EffectOAST uses the out-of-band interaction service.
	EffectOAST
	// EffectScan emits findings or queues scans.
	EffectScan
	// EffectSleep blocks the calling goroutine.
	EffectSleep
)

var effectNames = [...]string{
	EffectUnset:   "unset",
	EffectPure:    "pure",
	EffectNetwork: "network",
	EffectFS:      "fs",
	EffectExec:    "exec",
	EffectDBRead:  "db_read",
	EffectDBWrite: "db_write",
	EffectLLM:     "llm",
	EffectOAST:    "oast",
	EffectScan:    "scan",
	EffectSleep:   "sleep",
}

// String returns the effect's stable lowercase name.
func (e Effect) String() string {
	if int(e) < len(effectNames) {
		return effectNames[e]
	}
	return "unknown"
}

// Mode selects how SetupAPI wires the vigolium.* API onto a VM.
type Mode uint8

const (
	// ModeRuntime is a scan VM: handlers are real, and a namespace whose
	// dependency is missing (no HTTP client, no repository, …) is left out.
	ModeRuntime Mode = iota
	// ModeLoad is a load/lint VM: every namespace is registered so a script's
	// top-level code sees the same API shape it gets at runtime, EffectPure
	// handlers are real, and every other handler is a stub that returns an empty
	// value of its declared type and reports the call to APIOptions.OnLoadEffect.
	ModeLoad
)

// EffectCall is one effectful API call a script made while it was being loaded
// (that is, from top-level code, or from a function top-level code invoked).
type EffectCall struct {
	API    string // fully-qualified name, e.g. "vigolium.http.get"
	Effect Effect
	Line   int // 1-based line in the evaluated source, 0 if unknown
	Col    int // 1-based column, 0 if unknown
}
