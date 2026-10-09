package types

// DefaultMaxPerHost is the built-in per-host concurrency cap: the --max-per-host
// flag default, Options.MaxPerHost, scanning_pace.max_per_host, and the host
// limiter's floor when nothing chose a value.
//
// It had drifted to 50 (flag, Options), 40 (scanning_pace, so what `scan`
// actually ran at), 20 (the host limiter's own default) and 10 (the runner's
// fallback), so scan, scan-url and the REST server ran one target at four
// different widths. TestMaxPerHostDefaultsAgree pins every site to this one.
//
// Lives here rather than in pkg/core/ratelimit because pkg/types is the leaf
// every consumer (config, cli, runner, ratelimit) already reaches.
const DefaultMaxPerHost = 40
