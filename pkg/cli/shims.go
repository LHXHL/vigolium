package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/pkg/terminal"
)

// The most common failure when an LLM drives this engine is not a wrong flag —
// it is a child that was told to map a target, could not picture how, and went
// hunting the operator's host for ffuf / katana / nuclei / gau. It usually FINDS
// them, and then the whole mapping happens outside the engine: outside the
// pinned traffic database, outside the phase model, with flags nobody scoped.
//
// The instinctive response is enforcement — a "instead of X run Y" table, a
// route-rules file, a hook that refuses the binary, prompt-level tool-inventory
// rewriting. That is a lot of machinery to displace muscle memory, and it
// converts a capable action into a refusal.
//
// These shims accept the muscle memory instead. `vigolium ffuf -u URL/FUZZ -w
// list` parses the familiar argv, translates it to the native phase, writes to
// the pinned database, and prints one line saying what actually ran. A refusal
// becomes a redirect that just works.
//
// Three rules keep them honest:
//
//  1. They TRANSLATE, they do not reimplement. Each builds a vigolium command
//     line and runs it through the same cobra tree, so a shim can never drift
//     from the command it fronts.
//  2. They always print the translation. A silent redirect is a different
//     surprise, not a smaller one — the operator (or the agent reading the
//     output) has to be able to learn the native spelling.
//  3. An argument they do not understand is a hard error naming the native
//     command, never a silent drop. A dropped flag is a scan that ran with a
//     scope nobody chose, which is the failure this exists to prevent.

// shimSpec describes one aliased tool.
type shimSpec struct {
	name    string
	short   string
	example string
	// translate turns the tool's argv into a vigolium argv (without the leading
	// "vigolium"). It returns an error naming the native command when it meets an
	// argument it cannot map.
	translate func(args []string) ([]string, error)
}

func init() {
	for _, spec := range []shimSpec{
		{
			name:      "ffuf",
			short:     "Run content discovery using ffuf's argv (routed to `vigolium run discovery`)",
			example:   "vigolium ffuf -u https://target/FUZZ -w words.txt",
			translate: translateFFUF,
		},
		{
			name:      "nuclei",
			short:     "Run the known-issue scan using nuclei's argv (routed to `vigolium run known-issue-scan`)",
			example:   "vigolium nuclei -u https://target -severity high,critical",
			translate: translateNuclei,
		},
		{
			name:      "katana",
			short:     "Crawl using katana's argv (routed to `vigolium run spidering`)",
			example:   "vigolium katana -u https://target -d 3",
			translate: translateKatana,
		},
		{
			name:      "gau",
			short:     "Harvest archived URLs using gau's argv (routed to `vigolium run external-harvest`)",
			example:   "vigolium gau target.example.com",
			translate: translateGau,
		},
		{
			name:      "arjun",
			short:     "Discover parameters using arjun's argv (routed to `vigolium fuzz --fuzz param-name`)",
			example:   "vigolium arjun -u https://target/api",
			translate: translateArjun,
		},
	} {
		rootCmd.AddCommand(newShimCommand(spec))
	}
}

func newShimCommand(spec shimSpec) *cobra.Command {
	cmd := &cobra.Command{
		Use:   spec.name + " [flags]",
		Short: spec.short,
		Long: fmt.Sprintf(`Accepts the familiar %s command line and runs the equivalent native vigolium phase.

Results land in the pinned database and the phase model, which is the whole
point: a scan run through the real %s binary happens outside both, with flags
nobody scoped. The translated command is printed before it runs, so the native
spelling is always one invocation away.

Example:
  %s`, spec.name, spec.name, spec.example),
		// Unknown flags must reach translate rather than being rejected by cobra:
		// the whole surface is another tool's, and cobra knows none of it.
		DisableFlagParsing: true,
		Args:               cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// `--help` on a shim is a request to read this command's own help, not
			// to translate. DisableFlagParsing means cobra will not have handled it.
			for _, a := range args {
				if a == "-h" || a == "--help" {
					return cmd.Help()
				}
			}
			translated, err := spec.translate(args)
			if err != nil {
				return asUsageError(err)
			}
			fmt.Fprintf(os.Stderr, "%s %s %s\n",
				terminal.InfoSymbol(),
				terminal.Gray("routed to:"),
				terminal.BoldCyan("vigolium "+strings.Join(translated, " ")))
			// Silence the nested Execute's own error print: this RunE returns the
			// error, so the outer ExecuteC prints it. Without this a failing
			// translated command reports "Error: …" twice. Restored afterwards so
			// a later direct invocation is unaffected.
			prior := rootCmd.SilenceErrors
			rootCmd.SilenceErrors = true
			defer func() { rootCmd.SilenceErrors = prior }()
			rootCmd.SetArgs(translated)
			return rootCmd.Execute()
		},
	}
	return cmd
}

// shimArgs is a tiny scanner over another tool's argv. It exists so each
// translator reads as a table of recognized flags rather than as index
// arithmetic, and so "unknown flag" is one shared error instead of five.
type shimArgs struct {
	tool   string
	native string
	args   []string
	i      int
}

func newShimArgs(tool, native string, args []string) *shimArgs {
	return &shimArgs{tool: tool, native: native, args: args}
}

func (s *shimArgs) more() bool { return s.i < len(s.args) }
func (s *shimArgs) next() string {
	v := s.args[s.i]
	s.i++
	return v
}

// value returns the argument belonging to flag, accepting both `-u X` and
// `-u=X`. Returns an error rather than an empty string when the value is
// missing: a flag whose value silently became "" is a scope nobody chose.
func (s *shimArgs) value(flag string) (string, error) {
	if i := strings.IndexByte(flag, '='); i >= 0 {
		return flag[i+1:], nil
	}
	if !s.more() {
		return "", fmt.Errorf("%s: %s needs a value", s.tool, flag)
	}
	return s.next(), nil
}

// unknown is the shared refusal. It names the native command so the operator's
// next move is obvious, which is the difference between a redirect and a wall.
func (s *shimArgs) unknown(flag string) error {
	return fmt.Errorf("%s: %q has no vigolium equivalent in this shim.\n"+
		"Run the native command directly and pass what you need: vigolium %s --help",
		s.tool, flag, s.native)
}

// flagName strips a leading dash run and any =value suffix, so `-u`, `--u` and
// `-u=X` all normalize to "u". Both single- and double-dash forms are accepted
// because these tools disagree about which they use (ffuf and nuclei take
// single-dash long flags; katana takes both).
func flagName(arg string) string {
	name := strings.TrimLeft(arg, "-")
	if i := strings.IndexByte(name, '='); i >= 0 {
		name = name[:i]
	}
	return name
}

// shimRule is one recognized flag in a tool's argv.
//
// The five translators are one algorithm — scan argv, map a flag to its native
// spelling, emit its value — and writing that out per tool meant the same
// four-line `value(); if err; append` dance appeared thirty-odd times. A missed
// error return in any one of them silently yields "", i.e. the "scope nobody
// chose" failure this whole file exists to prevent. One driver, five tables.
type shimRule struct {
	// to is the native flag to emit. Empty means "recognize and swallow" — the
	// behaviour the tool asks for is already on, so accepting it is honest.
	to string
	// bare marks a flag that takes no value.
	bare bool
	// xform rewrites the value before it is emitted.
	xform func(string) string
	// capture accumulates the value instead of emitting it (targets, wordlists).
	capture *string
	// appendTo accumulates a repeatable value.
	appendTo *[]string
	// refuse, when non-empty, rejects the flag with this message. It is how a
	// shim says "this concept does not exist here" instead of approximating it —
	// the value is available as %s.
	refuse string
}

// drive scans argv against rules, appending translated flags to out. A bare
// (non-flag) argument goes to positional when non-nil, otherwise it is an error.
func (s *shimArgs) drive(out []string, rules map[string]shimRule, positional *[]string) ([]string, error) {
	for s.more() {
		arg := s.next()
		if positional != nil && !strings.HasPrefix(arg, "-") {
			*positional = append(*positional, arg)
			continue
		}
		rule, ok := rules[flagName(arg)]
		if !ok {
			return nil, s.unknown(arg)
		}
		if rule.bare {
			if rule.to != "" {
				out = append(out, rule.to)
			}
			continue
		}
		v, err := s.value(arg)
		if err != nil {
			return nil, err
		}
		if rule.refuse != "" {
			return nil, fmt.Errorf("%s: %s", s.tool, fmt.Sprintf(rule.refuse, v))
		}
		if rule.xform != nil {
			v = rule.xform(v)
		}
		switch {
		case rule.capture != nil:
			*rule.capture = v
		case rule.appendTo != nil:
			*rule.appendTo = append(*rule.appendTo, v)
		case rule.to != "":
			out = append(out, rule.to, v)
		}
	}
	return out, nil
}

// emitTargets appends one `-t <url>` pair per target.
func emitTargets(out []string, targets []string) []string {
	for _, t := range targets {
		out = append(out, "-t", t)
	}
	return out
}

func translateFFUF(args []string) ([]string, error) {
	s := newShimArgs("ffuf", "run discovery", args)
	var target, wordlist string
	out, err := s.drive([]string{"run", "discovery"}, map[string]shimRule{
		// ffuf marks the injection point with the literal FUZZ. Discovery fuzzes
		// paths from a wordlist by construction, so the marker is stripped rather
		// than honored — keeping it would make the target a URL containing the
		// word FUZZ.
		"u":   {capture: &target, xform: stripFuzzMarker},
		"url": {capture: &target, xform: stripFuzzMarker},
		// ffuf allows `-w list:KEYWORD`; only the path is meaningful here.
		"w":         {capture: &wordlist, xform: stripWordlistKeyword},
		"wordlist":  {capture: &wordlist, xform: stripWordlistKeyword},
		"t":         {to: "--concurrency"},
		"threads":   {to: "--concurrency"},
		"rate":      {to: "--rate-limit"},
		"H":         {to: "-H"},
		"header":    {to: "-H"},
		"x":         {to: "--proxy"},
		"proxy":     {to: "--proxy"},
		"timeout":   {to: "--timeout", xform: func(v string) string { return v + "s" }},
		"s":         {to: "--silent", bare: true},
		"silent":    {to: "--silent", bare: true},
		"recursion": {bare: true}, // discovery recurses by default
	}, nil)
	if err != nil {
		return nil, err
	}
	if target == "" {
		return nil, fmt.Errorf("ffuf: -u/--url is required")
	}
	out = append(out, "-t", target)
	if wordlist != "" {
		out = append(out, "--discovery-wordlist", wordlist)
	}
	return out, nil
}

func stripFuzzMarker(v string) string {
	return strings.TrimSuffix(strings.ReplaceAll(v, "FUZZ", ""), "/")
}

func stripWordlistKeyword(v string) string {
	if i := strings.LastIndexByte(v, ':'); i > 1 {
		return v[:i]
	}
	return v
}

func translateNuclei(args []string) ([]string, error) {
	s := newShimArgs("nuclei", "run known-issue-scan", args)
	var targets []string
	out, err := s.drive([]string{"run", "known-issue-scan"}, map[string]shimRule{
		"u":            {appendTo: &targets},
		"target":       {appendTo: &targets},
		"l":            {to: "-T"},
		"list":         {to: "-T"},
		"severity":     {to: "--known-issue-scan-severities"},
		"s":            {to: "--known-issue-scan-severities"},
		"tags":         {to: "--known-issue-scan-tags"},
		"etags":        {to: "--known-issue-scan-exclude-tags"},
		"exclude-tags": {to: "--known-issue-scan-exclude-tags"},
		"t":            {to: "--known-issue-scan-templates-dir"},
		"templates":    {to: "--known-issue-scan-templates-dir"},
		"rl":           {to: "--rate-limit"},
		"rate-limit":   {to: "--rate-limit"},
		"c":            {to: "--concurrency"},
		"concurrency":  {to: "--concurrency"},
		"H":            {to: "-H"},
		"header":       {to: "-H"},
		"proxy":        {to: "--proxy"},
		"silent":       {to: "--silent", bare: true},
		"j":            {to: "--json", bare: true},
		"jsonl":        {to: "--json", bare: true},
	}, nil)
	if err != nil {
		return nil, err
	}
	return emitTargets(out, targets), nil
}

func translateKatana(args []string) ([]string, error) {
	s := newShimArgs("katana", "run spidering", args)
	var targets []string
	out, err := s.drive([]string{"run", "spidering"}, map[string]shimRule{
		"u":              {appendTo: &targets},
		"list":           {appendTo: &targets},
		"c":              {to: "--concurrency"},
		"concurrency":    {to: "--concurrency"},
		"rl":             {to: "--rate-limit"},
		"rate-limit":     {to: "--rate-limit"},
		"H":              {to: "-H"},
		"headers":        {to: "-H"},
		"proxy":          {to: "--proxy"},
		"ct":             {to: "--spider-max-time"},
		"crawl-duration": {to: "--spider-max-time"},
		"silent":         {to: "--silent", bare: true},
		// Vigolium's spider is always browser-driven.
		"headless": {bare: true},
		"hl":       {bare: true},
		// The spider is a state machine over DOM snapshots, not a depth-limited
		// link follower, so there is no depth to set. Accepting and ignoring it
		// would be a silently different crawl; refusing names the knob that does
		// bound the crawl.
		"d":     {refuse: "-d/--depth (%s) has no equivalent — vigolium's spider is a state machine, not a depth-limited link follower. Bound the crawl with --spider-max-time instead"},
		"depth": {refuse: "-d/--depth (%s) has no equivalent — vigolium's spider is a state machine, not a depth-limited link follower. Bound the crawl with --spider-max-time instead"},
	}, nil)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("katana: -u is required")
	}
	return emitTargets(out, targets), nil
}

func translateGau(args []string) ([]string, error) {
	s := newShimArgs("gau", "run external-harvest", args)
	var targets []string
	out, err := s.drive([]string{"run", "external-harvest"}, map[string]shimRule{
		"threads": {to: "--concurrency"},
		"proxy":   {to: "--proxy"},
		"subs":    {to: "--follow-subdomains", bare: true},
	}, &targets)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("gau: a target domain is required")
	}
	// gau takes a bare domain; every vigolium phase takes a URL.
	for i, t := range targets {
		if !strings.Contains(t, "://") {
			targets[i] = "https://" + t
		}
	}
	return emitTargets(out, targets), nil
}

func translateArjun(args []string) ([]string, error) {
	s := newShimArgs("arjun", "fuzz", args)
	var target string
	out, err := s.drive([]string{"fuzz", "--fuzz", "param-name"}, map[string]shimRule{
		"u":        {capture: &target},
		"url":      {capture: &target},
		"m":        {to: "-X", xform: strings.ToUpper},
		"method":   {to: "-X", xform: strings.ToUpper},
		"w":        {to: "-w"},
		"wordlist": {to: "-w"},
		"t":        {to: "-c"},
		"threads":  {to: "-c"},
		"headers":  {to: "-H"},
		"d":        {refuse: "-d/--delay (%s) has no equivalent — pace the run with --rate-limit instead"},
		"delay":    {refuse: "-d/--delay (%s) has no equivalent — pace the run with --rate-limit instead"},
	}, nil)
	if err != nil {
		return nil, err
	}
	if target == "" {
		return nil, fmt.Errorf("arjun: -u/--url is required")
	}
	// --anomaly, because parameter discovery is exactly the case where the
	// interesting response is not knowable in advance: the caller cannot write a
	// matcher for a parameter they have not found yet.
	return append(out, "--anomaly", target), nil
}
