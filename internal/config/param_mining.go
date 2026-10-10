package config

// ParamMiningConfig bounds the param-mining phase: Arjun-style discovery of
// hidden parameters on the endpoints this scan recorded, run after discovery
// and before the assessment so injection modules test what it finds.
//
// The phase itself is switched on by --intensity deep or --param-mining
// (--param-mining=false or --skip param-mining turns it off); these keys only
// shape it. Every zero value means "use the built-in default".
type ParamMiningConfig struct {
	// MaxEndpointsPerHost caps how many endpoints per host are mined, chosen
	// by risk_score then surface_score. Default 50.
	MaxEndpointsPerHost int `yaml:"max_endpoints_per_host,omitempty"`
	// MaxRequestsPerEndpoint is the per-endpoint request budget, baselines
	// and confirmations included. Default 60.
	MaxRequestsPerEndpoint int `yaml:"max_requests_per_endpoint,omitempty"`
	// MaxWords caps the merged wordlist (target-derived names first, then the
	// built-in list and Wordlist). Default 0: no cap beyond the request budget.
	MaxWords int `yaml:"max_words,omitempty"`
	// Wordlist is an extra file of parameter names (one per line), tried after
	// the names the target's own JavaScript and traffic use and before the
	// built-in list.
	Wordlist string `yaml:"wordlist,omitempty"`
	// Concurrency is how many endpoints are mined at once. Default: the scan's
	// -c, capped at 10; per-host pressure is bounded by the host limiter.
	Concurrency int `yaml:"concurrency,omitempty"`
}

// Built-in param-mining defaults.
const (
	DefaultParamMiningEndpointsPerHost = 50
	DefaultParamMiningRequestsPerEnd   = 60
	maxParamMiningConcurrency          = 10
)

// EndpointsPerHost is MaxEndpointsPerHost with its default applied.
func (c ParamMiningConfig) EndpointsPerHost() int {
	if c.MaxEndpointsPerHost > 0 {
		return c.MaxEndpointsPerHost
	}
	return DefaultParamMiningEndpointsPerHost
}

// RequestsPerEndpoint is MaxRequestsPerEndpoint with its default applied.
func (c ParamMiningConfig) RequestsPerEndpoint() int {
	if c.MaxRequestsPerEndpoint > 0 {
		return c.MaxRequestsPerEndpoint
	}
	return DefaultParamMiningRequestsPerEnd
}

// Workers is the endpoint concurrency for a scan running with scanConcurrency
// workers.
func (c ParamMiningConfig) Workers(scanConcurrency int) int {
	n := c.Concurrency
	if n <= 0 {
		n = min(scanConcurrency, maxParamMiningConcurrency)
	}
	return max(n, 1)
}
