package config

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/authentication"
	"github.com/vigolium/vigolium/pkg/portsweep"
)

// ScanningStrategyConfig holds named scanning strategy presets.
// Each preset controls which scan phases are enabled.
type ScanningStrategyConfig struct {
	DefaultStrategy string                `yaml:"default_strategy"`
	HeuristicsCheck string                `yaml:"heuristics_check"`
	ScanningProfile string                `yaml:"scanning_profile"`
	ProfilesDir     string                `yaml:"profiles_dir"`
	Session         SessionStrategyConfig `yaml:"session"`
	ScanLogs        ScanLogsConfig        `yaml:"scan_logs"`
	HTTP            HTTPConfig            `yaml:"http"`
	PortSweep       PortSweepConfig       `yaml:"port_sweep"`
	Lite            StrategyPhases        `yaml:"lite"`
	Balanced        StrategyPhases        `yaml:"balanced"`
	Deep            StrategyPhases        `yaml:"deep"`
}

// PortSweepConfig controls the alternate-port sweep that runs at --intensity deep
// or under --follow-subdomains. For each original CLI target host it TCP-connects
// the configured ports concurrently, HTTP-confirms the open ones, and feeds any
// confirmed web services back into the scan as additional targets. A honeypot
// guard discards a host whose ports are nearly all open with near-identical
// responses (an all-ports-open tarpit).
type PortSweepConfig struct {
	// Ports is the list of alternate HTTP(S) ports probed per host.
	Ports []int `yaml:"ports"`
	// Concurrency is the max number of ports probed in parallel for one host.
	Concurrency int `yaml:"concurrency"`
	// DialTimeoutMs bounds each TCP connect.
	DialTimeoutMs int `yaml:"dial_timeout_ms"`
	// HTTPTimeoutMs bounds each HTTP confirmation request.
	HTTPTimeoutMs int `yaml:"http_timeout_ms"`
	// HoneypotRatio is the open/probed ratio at/above which a host is honeypot-
	// suspect (combined with a near-identical-response check). 0 disables the gate.
	HoneypotRatio float64 `yaml:"honeypot_ratio"`
}

// DefaultPortSweepConfig returns the built-in port-sweep defaults. The values are
// owned by the portsweep package (its single source of truth) so the config and
// the sweep engine never drift; portsweep.Sweep re-applies these for any field
// left zero, so a partial config block stays usable without a Resolve step.
func DefaultPortSweepConfig() PortSweepConfig {
	return PortSweepConfig{
		Ports:         append([]int(nil), portsweep.DefaultPorts...),
		Concurrency:   portsweep.DefaultConcurrency,
		DialTimeoutMs: portsweep.DefaultDialTimeoutMs,
		HTTPTimeoutMs: portsweep.DefaultHTTPTimeoutMs,
		HoneypotRatio: portsweep.DefaultHoneypotRatio,
	}
}

// SessionStrategyConfig controls how authentication sessions behave during scanning.
type SessionStrategyConfig struct {
	// SessionDir is the directory where session YAML files are stored.
	// Defaults to ~/.vigolium/sessions/. Used to resolve --session-file names
	// that are not absolute paths.
	SessionDir string `yaml:"session_dir"`

	// UseInDiscovery controls whether the primary session's headers are applied
	// during the discovery and spidering phases. When false, these phases run
	// unauthenticated even if a primary session is configured. Default: true.
	UseInDiscovery bool `yaml:"use_in_discovery"`

	// CompareEnabled controls whether compare sessions are activated for
	// cross-session IDOR/BOLA replay during the audit phase. Default: true.
	CompareEnabled bool `yaml:"compare_enabled"`

	// The three fields below are config-wide defaults for a session's `check`
	// block (pkg/authentication/loggedin.go): each fills the matching value a
	// session leaves unset, and a session's own value always wins. See
	// SessionDefaults.

	// ReauthInterval fills check.interval: the most often the active logged-in
	// probe runs proactively ("2m"; empty = only when traffic looks logged out).
	ReauthInterval string `yaml:"reauth_interval"`

	// ReauthOnStatus fills check.logged_out.status: response statuses that mark
	// the session as logged out (e.g. [401, 419, 440]).
	ReauthOnStatus []int `yaml:"reauth_on_status"`

	// ValidateURL fills check.url: the protected URL whose response tells a
	// logged-in session from an anonymous one (`vigolium auth check` probes it
	// when --url is not given). A path resolves against the target origin.
	ValidateURL string `yaml:"validate_url"`
}

// SessionDefaults returns the check-block defaults these settings supply, for
// authentication.Session.ApplyDefaults.
func (c *SessionStrategyConfig) SessionDefaults() (authentication.SessionDefaults, error) {
	if err := c.Validate(); err != nil {
		return authentication.SessionDefaults{}, err
	}
	d := authentication.SessionDefaults{
		ValidateURL:    strings.TrimSpace(c.ValidateURL),
		ReauthOnStatus: append([]int(nil), c.ReauthOnStatus...),
	}
	if v := strings.TrimSpace(c.ReauthInterval); v != "" {
		iv, _ := time.ParseDuration(v) // validated above
		d.ReauthInterval = iv
	}
	return d, nil
}

// Validate checks the session defaults: reauth_interval a non-negative
// duration, reauth_on_status real status codes, validate_url an http(s) URL or
// a path.
func (c *SessionStrategyConfig) Validate() error {
	if v := strings.TrimSpace(c.ReauthInterval); v != "" {
		iv, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("scanning_strategy.session.reauth_interval: invalid duration %q (want e.g. \"2m\")", v)
		}
		if iv < 0 {
			return fmt.Errorf("scanning_strategy.session.reauth_interval: must not be negative, got %q", v)
		}
	}
	for _, code := range c.ReauthOnStatus {
		if code < 100 || code > 599 {
			return fmt.Errorf("scanning_strategy.session.reauth_on_status: invalid HTTP status code %d", code)
		}
	}
	if v := strings.TrimSpace(c.ValidateURL); v != "" {
		u, err := url.Parse(v)
		switch {
		case err != nil:
			return fmt.Errorf("scanning_strategy.session.validate_url: %w", err)
		case u.IsAbs() && (u.Scheme != "http" && u.Scheme != "https" || u.Host == ""):
			return fmt.Errorf("scanning_strategy.session.validate_url: want an http(s) URL or a path starting with \"/\", got %q", v)
		case !u.IsAbs() && !strings.HasPrefix(v, "/"):
			return fmt.Errorf("scanning_strategy.session.validate_url: want an http(s) URL or a path starting with \"/\", got %q", v)
		}
	}
	return nil
}

// DefaultSessionStrategyConfig returns sensible defaults for session behavior.
func DefaultSessionStrategyConfig() *SessionStrategyConfig {
	return &SessionStrategyConfig{
		SessionDir:     "~/.vigolium/sessions/",
		UseInDiscovery: true,
		CompareEnabled: true,
	}
}

// StrategyPhases defines which phases are enabled for a strategy, and how hard
// that strategy is allowed to open.
type StrategyPhases struct {
	ExternalHarvesting bool `yaml:"external_harvesting"`
	Discovery          bool `yaml:"discovery"`
	Spidering          bool `yaml:"spidering"`
	KnownIssueScan     bool `yaml:"known_issue_scan"`
	DynamicAssessment  bool `yaml:"dynamic-assessment"`

	// Pace is the strategy's speed ceiling. Without it the dial selected which
	// modules ran and nothing else: `lite` and `balanced` opened a crawl
	// identically — concurrency 40, max-per-host 40, the same wordlists — so a
	// name every operator reads as "gentler on the target" was gentler in module
	// count alone. See StrategyPace for how it merges.
	Pace StrategyPace `yaml:"pace"`
}

// StrategyPace is a strategy's speed ceiling. Zero fields mean "this strategy
// imposes no ceiling of its own"; the built-in `balanced` and `deep` leave all
// three at zero, which is what keeps their behaviour unchanged.
//
// A ceiling NARROWS, it never widens: NarrowPace takes the minimum of the
// configured value and the strategy's, so choosing `lite` cannot make a scan
// faster than scanning_pace already allowed, and a config that is already
// gentler than `lite` is not dragged back up to it.
type StrategyPace struct {
	Concurrency int `yaml:"concurrency"`
	RateLimit   int `yaml:"rate_limit"`
	MaxPerHost  int `yaml:"max_per_host"`
}

// NarrowPace applies the strategy's ceiling to a configured value. A zero
// ceiling (or a zero configured value, which means "unlimited" for rate_limit)
// leaves the input untouched.
func NarrowPace(configured, ceiling int) int {
	if ceiling <= 0 {
		return configured
	}
	if configured <= 0 {
		// 0 is "no cap" for rate_limit. A strategy ceiling is exactly the thing
		// that should turn no-cap into a cap, so the ceiling wins here.
		return ceiling
	}
	return min(configured, ceiling)
}

// DefaultScanningStrategyConfig returns default configuration with balanced as default.
func DefaultScanningStrategyConfig() *ScanningStrategyConfig {
	return &ScanningStrategyConfig{
		DefaultStrategy: "balanced",
		HeuristicsCheck: "basic",
		ProfilesDir:     "~/.vigolium/profiles/",
		Session:         *DefaultSessionStrategyConfig(),
		ScanLogs:        *DefaultScanLogsConfig(),
		HTTP:            *DefaultHTTPConfig(),
		PortSweep:       DefaultPortSweepConfig(),
		Lite: StrategyPhases{
			ExternalHarvesting: false,
			Discovery:          false,
			KnownIssueScan:     false,
			DynamicAssessment:  true,
			// The only strategy that ships a ceiling. `balanced` is the baseline
			// (its pace IS scanning_pace) and `deep` is explicitly the one that
			// opens wide, so a ceiling on either would just restate or contradict
			// the config. `lite` is the one whose name promises restraint, and it
			// is the one that had none.
			Pace: StrategyPace{Concurrency: 10, RateLimit: 20, MaxPerHost: 10},
		},
		Balanced: StrategyPhases{
			ExternalHarvesting: false,
			Discovery:          true,
			Spidering:          true,
			KnownIssueScan:     true,
			DynamicAssessment:  true,
		},
		Deep: StrategyPhases{
			ExternalHarvesting: true,
			Discovery:          true,
			Spidering:          true,
			KnownIssueScan:     true,
			DynamicAssessment:  true,
		},
	}
}

// Validate checks that DefaultStrategy refers to a known strategy name.
func (c *ScanningStrategyConfig) Validate() error {
	if err := c.HTTP.HostErrors.Validate(); err != nil {
		return err
	}
	if err := c.Session.Validate(); err != nil {
		return err
	}
	if c.DefaultStrategy == "" {
		return nil
	}
	if _, ok := c.GetStrategy(c.DefaultStrategy); !ok {
		return fmt.Errorf("unknown default_strategy %q; valid names: %v", c.DefaultStrategy, c.StrategyNames())
	}
	return nil
}

// GetStrategy resolves a strategy name to its phases.
func (c *ScanningStrategyConfig) GetStrategy(name string) (StrategyPhases, bool) {
	switch name {
	case "lite":
		return c.Lite, true
	case "balanced":
		return c.Balanced, true
	case "deep":
		return c.Deep, true
	default:
		return StrategyPhases{}, false
	}
}

// StrategyNames returns a sorted list of known strategy names.
func (c *ScanningStrategyConfig) StrategyNames() []string {
	names := []string{"lite", "balanced", "deep"}
	sort.Strings(names)
	return names
}

// ResolveProfilePath resolves a profile name to a filesystem path.
// If name contains a path separator or starts with ~, it is treated as a path
// and expanded. Otherwise it is resolved as {profiles_dir}/{name}.yaml.
func (c *ScanningStrategyConfig) ResolveProfilePath(name string) string {
	if strings.Contains(name, "/") || strings.Contains(name, string(filepath.Separator)) || strings.HasPrefix(name, "~") {
		return ExpandPath(name)
	}
	dir := ExpandPath(c.ProfilesDir)
	return filepath.Join(dir, name+".yaml")
}

// ListProfiles returns the names (without .yaml extension) of profile files
// found in ProfilesDir. Returns nil and no error if the directory does not exist.
func (c *ScanningStrategyConfig) ListProfiles() ([]string, error) {
	dir := ExpandPath(c.ProfilesDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read profiles directory %s: %w", dir, err)
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			names = append(names, strings.TrimSuffix(strings.TrimSuffix(name, ".yaml"), ".yml"))
		}
	}
	sort.Strings(names)
	return names, nil
}

// ProfileDescription reads the first line of a profile YAML and extracts a
// description from a "# description: ..." comment. Returns "" if not found.
func ProfileDescription(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if after, ok := strings.CutPrefix(line, "# description:"); ok {
			return strings.TrimSpace(after)
		}
	}
	return ""
}
