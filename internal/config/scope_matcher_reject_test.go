package config

import "testing"

// rejectFixture is one scope configuration the RejectReason tests evaluate.
type rejectFixture struct {
	name    string
	cfg     func() ScopeConfig
	targets []string
	allow   []string // hosts added through AllowHost
}

func rejectFixtures() []rejectFixture {
	base := func(mut func(*ScopeConfig)) func() ScopeConfig {
		return func() ScopeConfig {
			c := *DefaultScopeConfig()
			if mut != nil {
				mut(&c)
			}
			return c
		}
	}
	return []rejectFixture{
		{name: "defaults", cfg: base(nil)},
		{name: "defaults with targets", cfg: base(nil), targets: []string{"https://app.example.com"}},
		{name: "strict origin", cfg: base(func(c *ScopeConfig) { c.CLIOriginMode = "strict" }),
			targets: []string{"https://app.example.com", "http://10.0.0.5:8080"}},
		{name: "relaxed origin", cfg: base(func(c *ScopeConfig) { c.CLIOriginMode = "relaxed" }),
			targets: []string{"https://app.example.com"}},
		{name: "host include", cfg: base(func(c *ScopeConfig) {
			c.Host = ScopeRule{Include: []string{"*.example.com", "example.com"}}
		}), targets: []string{"https://app.example.com"}},
		{name: "host exclude beats include and origin", cfg: base(func(c *ScopeConfig) {
			c.Host = ScopeRule{Include: []string{"*.example.com"}, Exclude: []string{"admin.example.com"}}
		}), targets: []string{"https://admin.example.com"}},
		{name: "corrupted include pattern", cfg: base(func(c *ScopeConfig) {
			c.Host = ScopeRule{Include: []string{"[a.example"}}
		})},
		{name: "path rules", cfg: base(func(c *ScopeConfig) {
			c.Path = ScopeRule{Include: []string{"/api/*"}, Exclude: []string{"/api/logout*"}}
		})},
		{name: "allow-set overrides host rules", cfg: base(func(c *ScopeConfig) {
			c.Host = ScopeRule{Include: []string{"nomatch.example"}, Exclude: []string{"dyn.other.org"}}
			c.CLIOriginMode = "strict"
		}), targets: []string{"https://app.example.com"}, allow: []string{"DYN.other.org"}},
		{name: "static filter off", cfg: base(func(c *ScopeConfig) { c.IgnoreStaticFile = false })},
	}
}

var rejectProbes = []struct{ host, path string }{
	{"app.example.com", "/"},
	{"app.example.com", "/api/users?id=1"},
	{"app.example.com", "/api/logout"},
	{"app.example.com", "/logo.png"},
	{"APP.Example.COM", "/"},
	{"admin.example.com", "/"},
	{"example.com", "/"},
	{"cdn.example.net", "/"},
	{"example.io", "/"},
	{"10.0.0.5", "/"},
	{"10.0.0.6", "/"},
	{"dyn.other.org", "/"},
	{"dyn.other.org", "/style.png"},
	{"[a.example", "/"},
	{"localhost", "/"},
	{"", "/"},
	{"app.example.com", ""},
}

// TestRejectReasonAgreesWithInScopeRequest is the contract RejectReason exists
// under: it explains InScopeRequest, so the two must give the same verdict on
// every input. A drift here means a target is reported as admitted and then
// silently dropped (or the reverse).
func TestRejectReasonAgreesWithInScopeRequest(t *testing.T) {
	t.Parallel()
	for _, fx := range rejectFixtures() {
		m := NewScopeMatcher(fx.cfg(), fx.targets...)
		for _, h := range fx.allow {
			m.AllowHost(h)
		}
		for _, p := range rejectProbes {
			reason := m.RejectReason(p.host, p.path)
			in := m.InScopeRequest(p.host, p.path, "", "")
			if (reason == "") != in {
				t.Errorf("%s: RejectReason(%q,%q)=%q but InScopeRequest=%v",
					fx.name, p.host, p.path, reason, in)
			}
		}
	}
}

func TestRejectReasonRules(t *testing.T) {
	t.Parallel()
	fixtures := map[string]rejectFixture{}
	for _, fx := range rejectFixtures() {
		fixtures[fx.name] = fx
	}
	cases := []struct {
		fixture, host, path, want string
	}{
		{"defaults", "anything.test", "/", ""},
		{"defaults", "anything.test", "/logo.png", ScopeRuleStaticFile},
		{"static filter off", "anything.test", "/logo.png", ""},
		{"defaults with targets", "api.example.com", "/", ""},
		{"defaults with targets", "evil.test", "/", ScopeRuleCLIOriginMode},
		{"strict origin", "api.example.com", "/", ScopeRuleCLIOriginMode},
		{"strict origin", "app.example.com", "/", ""},
		{"strict origin", "10.0.0.5", "/", ""},
		{"strict origin", "10.0.0.6", "/", ScopeRuleCLIOriginMode},
		{"host include", "app.example.com", "/", ""},
		{"host include", "nomatch.test", "/", ScopeRuleHostInclude},
		// host.exclude outranks both the include list and the origin index,
		// even when the excluded host is the CLI target itself.
		{"host exclude beats include and origin", "admin.example.com", "/", ScopeRuleHostExclude},
		// filepath.Match returns ErrBadPattern for the unclosed bracket, which
		// globMatch reads as "no match": the include list admits nothing.
		{"corrupted include pattern", "a.example", "/", ScopeRuleHostInclude},
		{"path rules", "x.test", "/api/users", ""},
		{"path rules", "x.test", "/api/logout", ScopeRulePathExclude},
		{"path rules", "x.test", "/admin", ScopeRulePathInclude},
		{"allow-set overrides host rules", "dyn.other.org", "/", ""},
		{"allow-set overrides host rules", "dyn.other.org", "/a.png", ScopeRuleStaticFile},
		{"allow-set overrides host rules", "app.example.com", "/", ScopeRuleHostInclude},
	}
	for _, tc := range cases {
		fx := fixtures[tc.fixture]
		m := NewScopeMatcher(fx.cfg(), fx.targets...)
		for _, h := range fx.allow {
			m.AllowHost(h)
		}
		if got := m.RejectReason(tc.host, tc.path); got != tc.want {
			t.Errorf("%s: RejectReason(%q,%q) = %q, want %q", tc.fixture, tc.host, tc.path, got, tc.want)
		}
	}
}

func TestRejectReasonNilMatcher(t *testing.T) {
	t.Parallel()
	var m *ScopeMatcher
	if got := m.RejectReason("example.com", "/"); got != "" {
		t.Fatalf("nil matcher RejectReason = %q, want empty", got)
	}
}
