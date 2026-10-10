package sqli_time_blind

// RiskyPayloads reports the risk:high share of the time payload templates
// (modules.RiskyPayloadReporter), for the scan plan.
func (m *Module) RiskyPayloads() (risky, total int) {
	for _, set := range [][]timePair{stringPayloads, numericPayloads} {
		for _, p := range set {
			total++
			if p.risk == riskHigh {
				risky++
			}
		}
	}
	return risky, total
}
