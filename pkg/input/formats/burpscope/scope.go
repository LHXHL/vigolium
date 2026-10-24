// Package burpscope reads the target scope out of a Burp Suite project- or
// user-config JSON export and expands its include rules into concrete seed
// URLs.
//
// This is the file a bug-bounty program hands out as "the Burp scope": a
// {"target":{"scope":{"include":[…],"exclude":[…]}}} document whose rules are
// regexes over protocol/host/port/file. It is not a Burp project file (.burp,
// proprietary binary) and it carries no traffic — see the burpxml format for
// a saved Proxy history.
//
// Only include rules with a literal host become targets. A wildcard host
// ("^.*\.example\.com$") names a set, not a server, and inventing a member of
// that set — the apex, say — would send traffic at a host the scope never
// listed. Those rules are reported instead (Result.WildcardHosts) so the
// operator can seed them deliberately.
package burpscope

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"go.uber.org/zap"
)

// maxFileBytes caps what Sniff/Load will read. Scope exports are kilobytes;
// anything past this is some other JSON that happens to share key names.
const maxFileBytes = 16 << 20

// Rule is one include/exclude entry. Advanced mode populates the regex fields;
// simple mode populates Prefix with a literal URL prefix instead.
type Rule struct {
	Enabled  *bool  `json:"enabled"`
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	File     string `json:"file"`
	Prefix   string `json:"prefix"`
}

// isEnabled treats a missing "enabled" key as on. Burp always writes the
// field; a hand-edited file that omits it means "use this rule", and defaulting
// to off would silently drop every target.
func (r Rule) isEnabled() bool { return r.Enabled == nil || *r.Enabled }

// Scope is the scope section of a Burp config.
type Scope struct {
	AdvancedMode bool   `json:"advanced_mode"`
	Include      []Rule `json:"include"`
	Exclude      []Rule `json:"exclude"`
}

type projectConfig struct {
	Target struct {
		Scope Scope `json:"scope"`
	} `json:"target"`
}

// Result is the outcome of expanding a scope file.
type Result struct {
	// URLs are the seed targets, deduplicated, in include-rule order.
	URLs []string
	// WildcardHosts lists include rules whose host is a pattern rather than a
	// name, rendered for display ("*.example.com").
	WildcardHosts []string
	// Excluded counts candidates dropped by an exclude rule.
	Excluded int
	// CollapsedHTTP counts http:// candidates dropped because the same host and
	// path is also in scope over https://.
	CollapsedHTTP int
	// Disabled counts include rules turned off in Burp.
	Disabled int
}

// Sniff reports whether data is a Burp scope export. It is deliberately strict:
// the document must carry a target.scope object with at least one rule, so a
// HAR or Postman collection cannot be mistaken for one.
func Sniff(data []byte) bool {
	if !bytes.Contains(data, []byte(`"scope"`)) || !bytes.Contains(data, []byte(`"target"`)) {
		return false
	}
	var cfg projectConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return false
	}
	return len(cfg.Target.Scope.Include)+len(cfg.Target.Scope.Exclude) > 0
}

// SniffFile reports whether the file at path is a Burp scope export.
//
// Only a regular file is sniffed. Reading a pipe to sniff it consumes the
// content the caller's own read was going to get, and on macOS stat reports a
// FIFO's buffered byte count as its size, so the size checks below do not keep
// a pipe out on their own.
func SniffFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > maxFileBytes {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return Sniff(data)
}

// Load parses a Burp scope export.
func Load(path string) (*Scope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read burp scope file %q: %w", path, err)
	}
	var cfg projectConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse burp scope file %q: %w", path, err)
	}
	sc := cfg.Target.Scope
	if len(sc.Include)+len(sc.Exclude) == 0 {
		return nil, fmt.Errorf("burp scope file %q has no target.scope rules", path)
	}
	return &sc, nil
}

// TargetURLs loads and expands the scope file at path.
func TargetURLs(path string) (*Result, error) {
	sc, err := Load(path)
	if err != nil {
		return nil, err
	}
	return Expand(sc), nil
}

// candidate is one derived origin+path before dedup and exclusion.
type candidate struct {
	scheme string
	host   string
	port   int
	path   string
}

// url renders the candidate, omitting the port when it is the scheme default.
func (c candidate) url() string {
	if (c.scheme == "https" && c.port == 443) || (c.scheme == "http" && c.port == 80) {
		return c.scheme + "://" + c.host + c.path
	}
	return c.scheme + "://" + c.host + ":" + strconv.Itoa(c.port) + c.path
}

// Expand turns include rules into seed URLs, dropping anything an exclude rule
// covers.
func Expand(sc *Scope) *Result {
	res := &Result{}
	excludes := compileMatchers(sc.Exclude)

	seen := make(map[string]struct{})
	wildcards := make(map[string]struct{})
	// httpsSeen keys the https origins so the http counterpart of the same
	// host+path can be collapsed away afterwards.
	httpsSeen := make(map[string]struct{})
	type kept struct {
		url string
		c   candidate
	}
	var order []kept

	for _, r := range sc.Include {
		if !r.isEnabled() {
			res.Disabled++
			continue
		}
		cands, wildcard := candidatesFor(r)
		if wildcard != "" {
			if _, dup := wildcards[wildcard]; !dup {
				wildcards[wildcard] = struct{}{}
				res.WildcardHosts = append(res.WildcardHosts, wildcard)
			}
			continue
		}
		for _, c := range cands {
			u := c.url()
			if _, dup := seen[u]; dup {
				continue
			}
			seen[u] = struct{}{}
			if matchesAny(excludes, c, u) {
				res.Excluded++
				continue
			}
			if c.scheme == "https" {
				httpsSeen[c.host+c.path] = struct{}{}
			}
			order = append(order, kept{url: u, c: c})
		}
	}

	// Burp scope files list http and https for every host, and the http entry is
	// virtually always a redirect to the https one. Scanning both doubles the
	// work for one target. Collapse only the exact counterpart — an explicit
	// non-default port stays, since that is a different service.
	for _, k := range order {
		if k.c.scheme == "http" && k.c.port == 80 {
			if _, ok := httpsSeen[k.c.host+k.c.path]; ok {
				res.CollapsedHTTP++
				continue
			}
		}
		res.URLs = append(res.URLs, k.url)
	}
	return res
}

// candidatesFor derives the URLs one include rule describes. A non-empty
// wildcard return means the rule named a pattern rather than a host.
func candidatesFor(r Rule) (cands []candidate, wildcard string) {
	// Simple (non-advanced) mode: the rule is already a literal URL prefix.
	if prefix := strings.TrimSpace(r.Prefix); prefix != "" {
		c, ok := candidateFromPrefix(prefix)
		if !ok {
			return nil, prefix
		}
		return []candidate{c}, ""
	}

	host, ok := literalPattern(r.Host)
	if !ok {
		return nil, displayPattern(r.Host)
	}

	path := literalPathPrefix(r.File)
	port, hasPort := 0, false
	if p, ok := literalPattern(r.Port); ok {
		if n, err := strconv.Atoi(p); err == nil && n > 0 && n <= 65535 {
			port, hasPort = n, true
		}
	}

	for _, scheme := range schemesFor(r.Protocol, port) {
		c := candidate{scheme: scheme, host: host, path: path, port: port}
		if !hasPort {
			c.port = defaultPort(scheme)
		}
		cands = append(cands, c)
	}
	return cands, ""
}

// schemesFor resolves the rule's protocol. Burp's "any" pairs with a port in
// practice, so a rule pinned to 80 or 443 resolves to the matching scheme
// rather than emitting both.
func schemesFor(protocol string, port int) []string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "http":
		return []string{"http"}
	case "https":
		return []string{"https"}
	}
	switch port {
	case 80:
		return []string{"http"}
	case 443:
		return []string{"https"}
	}
	return []string{"http", "https"}
}

func defaultPort(scheme string) int {
	if scheme == "https" {
		return 443
	}
	return 80
}

// candidateFromPrefix parses a simple-mode rule ("https://example.com/api/").
func candidateFromPrefix(prefix string) (candidate, bool) {
	scheme, rest, ok := strings.Cut(prefix, "://")
	if !ok {
		return candidate{}, false
	}
	scheme = strings.ToLower(scheme)
	if scheme != "http" && scheme != "https" {
		return candidate{}, false
	}
	authority, path, hasPath := strings.Cut(rest, "/")
	if hasPath {
		path = "/" + path
	} else {
		path = "/"
	}
	host := authority
	port := defaultPort(scheme)
	if h, p, found := strings.Cut(authority, ":"); found {
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n > 65535 {
			return candidate{}, false
		}
		host, port = h, n
	}
	if host == "" || strings.ContainsAny(host, "*?") {
		return candidate{}, false
	}
	return candidate{scheme: scheme, host: host, port: port, path: path}, true
}

// matcher is a compiled exclude rule.
type matcher struct {
	protocol string
	host     *regexp.Regexp
	port     *regexp.Regexp
	file     *regexp.Regexp
	prefix   string
}

// compileMatchers turns exclude rules into matchers. A rule whose regex Go
// cannot compile is dropped with a warning rather than failing the run: an
// unusable exclude must not take the whole target list down with it, and the
// operator still sees that the rule was not applied.
func compileMatchers(rules []Rule) []matcher {
	var out []matcher
	for _, r := range rules {
		if !r.isEnabled() {
			continue
		}
		if prefix := strings.TrimSpace(r.Prefix); prefix != "" {
			out = append(out, matcher{prefix: prefix})
			continue
		}
		m := matcher{protocol: strings.ToLower(strings.TrimSpace(r.Protocol))}
		bad := false
		for _, f := range []struct {
			pattern string
			dst     **regexp.Regexp
		}{{r.Host, &m.host}, {r.Port, &m.port}, {r.File, &m.file}} {
			if strings.TrimSpace(f.pattern) == "" {
				continue
			}
			re, err := regexp.Compile(f.pattern)
			if err != nil {
				zap.L().Warn("burpscope: skipping exclude rule with uncompilable pattern",
					zap.String("pattern", f.pattern), zap.Error(err))
				bad = true
				break
			}
			*f.dst = re
		}
		if bad || m.host == nil {
			continue
		}
		out = append(out, m)
	}
	return out
}

func matchesAny(ms []matcher, c candidate, u string) bool {
	for _, m := range ms {
		if m.prefix != "" {
			if strings.HasPrefix(u, m.prefix) {
				return true
			}
			continue
		}
		if m.protocol != "" && m.protocol != "any" && m.protocol != c.scheme {
			continue
		}
		if !m.host.MatchString(c.host) {
			continue
		}
		if m.port != nil && !m.port.MatchString(strconv.Itoa(c.port)) {
			continue
		}
		if m.file != nil && !m.file.MatchString(c.path) {
			continue
		}
		return true
	}
	return false
}

// Stat is one entry in the expansion tally: a count and the noun it counts.
// Keeping the two apart lets a console caller colour the number without
// re-parsing a rendered string, while the log keeps a plain one.
type Stat struct {
	Count int
	Label string
}

// Stats returns the tally of what the expansion kept and dropped, so a skipped
// wildcard or a collapsed scheme is never silent. The wildcard hosts themselves
// are left to WildcardSample: a scope with 17 of them turns a one-line summary
// into a paragraph.
func (r *Result) Stats() []Stat {
	stats := []Stat{{len(r.URLs), pluralize(len(r.URLs), "target", "targets")}}
	if n := len(r.WildcardHosts); n > 0 {
		stats = append(stats, Stat{n, pluralize(n, "wildcard host skipped", "wildcard hosts skipped")})
	}
	if r.CollapsedHTTP > 0 {
		stats = append(stats, Stat{r.CollapsedHTTP, "http→https collapsed"})
	}
	if r.Excluded > 0 {
		stats = append(stats, Stat{r.Excluded, "excluded"})
	}
	if r.Disabled > 0 {
		stats = append(stats, Stat{r.Disabled, "disabled"})
	}
	return stats
}

// Summary renders Stats as one uncoloured line, for logs.
func (r *Result) Summary() string {
	stats := r.Stats()
	parts := make([]string, 0, len(stats))
	for _, s := range stats {
		parts = append(parts, fmt.Sprintf("%d %s", s.Count, s.Label))
	}
	return strings.Join(parts, " · ")
}

func pluralize(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}

// WildcardSample renders up to max wildcard host patterns, sorted for stable
// output, with a "+N" tail standing in for the rest.
func (r *Result) WildcardSample(max int) string {
	if len(r.WildcardHosts) == 0 {
		return ""
	}
	hosts := append([]string(nil), r.WildcardHosts...)
	sort.Strings(hosts)
	if max <= 0 || len(hosts) <= max {
		return strings.Join(hosts, ", ")
	}
	return fmt.Sprintf("%s, +%d", strings.Join(hosts[:max], ", "), len(hosts)-max)
}
