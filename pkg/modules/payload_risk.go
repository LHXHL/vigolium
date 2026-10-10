package modules

// RiskyPayloadReporter is implemented by a module that keeps running below
// --intensity deep but holds back some of its payloads there (the risk:high
// templates: OR-per-row and stacked forms), sending them only at deep or with
// --allow-risky-payloads. The scan plan reports the withheld share so a
// dry run shows what a balanced scan does not try.
type RiskyPayloadReporter interface {
	// RiskyPayloads returns how many of the module's payload templates are
	// risk:high, out of how many in total.
	RiskyPayloads() (risky, total int)
}
