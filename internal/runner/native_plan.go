package runner

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/types"
)

type NativePhase string

const (
	PhaseHeuristicsCheck   NativePhase = "heuristics-check"
	PhasePortSweep         NativePhase = "port-sweep"
	PhaseExternalHarvest   NativePhase = "external-harvest"
	PhaseSpidering         NativePhase = "spidering"
	PhaseProbe             NativePhase = "probe"
	PhaseDiscovery         NativePhase = "discovery"
	PhaseTargetedReSpider  NativePhase = "targeted-respider"
	PhaseSeed              NativePhase = "seed"
	PhaseKnownIssueScan    NativePhase = "known-issue-scan"
	PhaseDynamicAssessment NativePhase = "dynamic-assessment"
)

// nativePhaseSpelling is one canonical phase id plus every alternative spelling
// accepted for it.
type nativePhaseSpelling struct {
	Canonical string
	Aliases   []string
	// Skippable reports whether --skip accepts this phase.
	Skippable bool
	// Internal marks a step the plan schedules on its own gates (seed fills in
	// for a skipped ingestion, the re-spider rides on spidering). It is listed so
	// every phase.* id a scan can emit is discoverable, is accepted by --skip
	// when Skippable, and is never accepted by --only: it cannot run alone.
	Internal bool
}

// onlyAccepted reports whether --only (and `run <phase>`) accepts this phase.
func (p nativePhaseSpelling) onlyAccepted() bool { return !p.Internal }

// nativePhaseVocabulary is the SINGLE owner of the phase-name vocabulary. Every
// consumer derives from it: NormalizeNativePhase maps a spelling to its canonical
// id, the --only/--skip valid-phase lists in error messages are rendered from it,
// and `run <phase>` inherits both. Keeping one table is what stops the two halves
// from drifting — the asymmetry it replaced had `discover` normalizing to
// discovery while `spider` did not normalize at all, so `run discover` worked and
// `run spider` failed with "invalid --only value" for no reason a user could see.
//
// Aliases are the spellings an operator (or a coding agent driving the CLI)
// actually reaches for: the gerund of each phase, the internal engine names
// (deparos/spitolas), and the vocabulary borrowed from the tools each phase
// replaces (crawl, cve). The list is deliberately generous — a rejected synonym
// costs a round trip, while an extra accepted one costs nothing.
var nativePhaseVocabulary = []nativePhaseSpelling{
	{Canonical: "ingestion", Aliases: []string{"ingest", "ingesting"}, Skippable: true},
	{Canonical: "probe", Aliases: []string{"probing", "httpx", "alive", "sweep"}, Skippable: true},
	{Canonical: "discovery", Aliases: []string{"discover", "discovering", "deparos"}, Skippable: true},
	{Canonical: "external-harvest", Aliases: []string{"harvest", "harvesting", "external-harvester", "external_harvester"}, Skippable: true},
	{Canonical: "spidering", Aliases: []string{"spider", "spitolas", "crawl", "crawling", "crawler"}, Skippable: true},
	{Canonical: "known-issue-scan", Aliases: []string{"cve", "kis", "known-issue", "known-issues"}, Skippable: true},
	{Canonical: "dynamic-assessment", Aliases: []string{"dast", "audit", "assessment", "assess"}, Skippable: true},
	// --skip extension turns extensions off for the run even when the config or
	// --ext enabled them; --only extension narrows the assessment to them.
	{Canonical: "extension", Aliases: []string{"ext", "extensions"}, Skippable: true},
	// The rows below are steps BuildNativeScanPlan schedules; they appear on
	// phase.started/phase.finished, so they must be nameable here.
	{Canonical: "heuristics-check", Aliases: []string{"heuristics", "heuristic"}, Skippable: true},
	{Canonical: "port-sweep", Aliases: []string{"ports", "portsweep", "port-scan"}, Skippable: true},
	{Canonical: "targeted-respider", Aliases: []string{"respider", "re-spider"}, Skippable: true, Internal: true},
	{Canonical: "seed", Skippable: false, Internal: true},
	// preflight is reserved for the target reachability check that runs before
	// any phase. --skip preflight is accepted now (opts.SkipPreflight); the step
	// itself is not in the plan yet.
	{Canonical: "preflight", Skippable: true, Internal: true},
}

// nativePhaseAliasIndex resolves any accepted spelling (canonical included) to
// its canonical id. Built once from nativePhaseVocabulary.
var nativePhaseAliasIndex = func() map[string]string {
	idx := make(map[string]string)
	for _, p := range nativePhaseVocabulary {
		idx[p.Canonical] = p.Canonical
		for _, a := range p.Aliases {
			idx[a] = p.Canonical
		}
	}
	return idx
}()

// PhaseSpelling is the public projection of one vocabulary entry, for callers
// that need the structure rather than a rendered line — notably the machine
// output of `vigolium strategy`, which is how a caller discovers what --only
// and --skip accept without parsing help text.
type PhaseSpelling struct {
	Canonical string   `json:"canonical"`
	Aliases   []string `json:"aliases,omitempty"`
	Skippable bool     `json:"skippable"`
	// Internal: scheduled by the plan on its own gates; never accepted by --only.
	Internal bool `json:"internal"`
	// OnlyAccepted reports whether --only / `run <phase>` accepts this phase.
	OnlyAccepted bool `json:"only_accepted"`
}

// PhaseVocabulary returns the accepted phase spellings, derived from the same
// single table every other consumer reads. Building the machine list here rather
// than restating it in pkg/cli is what keeps a new phase from being runnable but
// undiscoverable.
func PhaseVocabulary() []PhaseSpelling {
	out := make([]PhaseSpelling, 0, len(nativePhaseVocabulary))
	for _, p := range nativePhaseVocabulary {
		aliases := append([]string(nil), p.Aliases...)
		out = append(out, PhaseSpelling{
			Canonical:    p.Canonical,
			Aliases:      aliases,
			Skippable:    p.Skippable,
			Internal:     p.Internal,
			OnlyAccepted: p.onlyAccepted(),
		})
	}
	return out
}

// acceptedBy reports whether the --skip (forSkip) or --only (!forSkip) list
// includes this phase.
func (p nativePhaseSpelling) acceptedBy(forSkip bool) bool {
	if forSkip {
		return p.Skippable
	}
	return p.onlyAccepted()
}

// PhaseVocabularyLines renders one "canonical (alias, alias)" entry per phase,
// for help text that lists them vertically. forSkip selects the phases --skip
// accepts; false selects the phases --only accepts. Returned as lines rather
// than a joined string because the alias lists are themselves comma-separated —
// splitting the flat form on ", " to lay it out would break entries apart
// mid-list.
func PhaseVocabularyLines(forSkip bool) []string {
	lines := make([]string, 0, len(nativePhaseVocabulary))
	for _, p := range nativePhaseVocabulary {
		if !p.acceptedBy(forSkip) {
			continue
		}
		entry := p.Canonical
		if len(p.Aliases) > 0 {
			entry += " (" + strings.Join(p.Aliases, ", ") + ")"
		}
		lines = append(lines, entry)
	}
	return lines
}

// phaseVocabularyDesc renders the vocabulary as "canonical (alias, alias), …".
func phaseVocabularyDesc(forSkip bool) string {
	return strings.Join(PhaseVocabularyLines(forSkip), ", ")
}

// PhaseNamesDesc renders the canonical phase ids alone, comma-separated. Flag
// help uses this (the full alias vocabulary is too long for one --help line);
// the error a wrong value produces quotes ValidOnlyPhasesDesc/ValidSkipPhasesDesc
// instead, which spells every accepted alias out.
func PhaseNamesDesc(forSkip bool) string {
	names := make([]string, 0, len(nativePhaseVocabulary))
	for _, p := range nativePhaseVocabulary {
		if !p.acceptedBy(forSkip) {
			continue
		}
		names = append(names, p.Canonical)
	}
	return strings.Join(names, ", ")
}

// ValidOnlyPhasesDesc and ValidSkipPhasesDesc are the human-readable phase lists
// rendered in --only/--skip validation error messages. Derived from
// nativePhaseVocabulary rather than hand-written, so a spelling that works can
// never go unlisted and a listed one can never fail to resolve.
var (
	ValidOnlyPhasesDesc = phaseVocabularyDesc(false)
	ValidSkipPhasesDesc = phaseVocabularyDesc(true)
)

type NativePhaseStep struct {
	Phase   NativePhase
	Enabled bool

	// SkipsTarget marks a phase that never sends a request to the scan target.
	// Declared here, in the same literal as the phase's own gate, rather than in
	// a side table keyed by phase: this file is the single owner of the phase
	// vocabulary, and a second per-phase map is exactly how the vocabulary and
	// the plan drifted apart before. A new phase has to answer the question
	// where it is declared.
	SkipsTarget bool
}

type NativeScanPlan struct {
	Steps []NativePhaseStep
}

func BuildNativeScanPlan(opts *types.Options) NativeScanPlan {
	steps := []NativePhaseStep{
		{Phase: PhaseHeuristicsCheck, Enabled: opts.HeuristicsCheck != "" && opts.HeuristicsCheck != "none"},
		// Alternate-port sweep of the original CLI target hosts. Independent of
		// the heuristics level — gated on deep / --follow-subdomains, or asked
		// for by name with --only port-sweep — so any confirmed extra web
		// services are appended to the target set before the ingestion/scan
		// phases consume it. --skip port-sweep, and any --only that does not
		// list it, set SkipPortSweep.
		{Phase: PhasePortSweep, Enabled: !opts.SkipPortSweep &&
			(opts.FollowSubdomains || strings.EqualFold(opts.Intensity, "deep") || OnlyPhaseSet(opts.OnlyPhase)[string(PhasePortSweep)])},
		// ExternalHarvest only queries third-party archives and OSINT sources
		// ABOUT the target; it never contacts it. See SendsTargetTraffic.
		{Phase: PhaseExternalHarvest, Enabled: opts.ExternalHarvestEnabled, SkipsTarget: true},
		{Phase: PhaseSpidering, Enabled: opts.SpideringEnabled},
		// Host sweep: one request per target, passive-only, no content discovery.
		// Placed before discovery so a full scan's later phases see the probe's
		// records (and its followed-redirect targets) already in the corpus.
		// Opt-in — a normal scan's discovery phase already fetches every target.
		{Phase: PhaseProbe, Enabled: opts.ProbeEnabled},
		{Phase: PhaseDiscovery, Enabled: !opts.SkipIngestion},
		// Re-spider rich/SPA routes that discovery surfaced after the one-shot
		// browser crawl. Rides along only when browsers are allowed (spidering
		// enabled), discovery ran, and an assessment phase will consume the new
		// records. The config toggle + runtime gates are checked in the phase.
		{Phase: PhaseTargetedReSpider, Enabled: opts.SpideringEnabled && !opts.SkipIngestion && !opts.SkipDynamicAssessment && !opts.SkipTargetedRespider},
		{Phase: PhaseSeed, Enabled: opts.SkipIngestion && !opts.ScanOnReceive && (opts.KnownIssueScanEnabled || !opts.SkipDynamicAssessment)},
		{Phase: PhaseDynamicAssessment, Enabled: !opts.SkipDynamicAssessment},
		{Phase: PhaseKnownIssueScan, Enabled: opts.KnownIssueScanEnabled},
	}
	return NativeScanPlan{Steps: steps}
}

// SendsTargetTraffic reports whether any enabled step in the plan will send a
// request to the scan target. Everything but ExternalHarvest reaches it,
// directly or through the shared requester, and so is affected by session
// headers and request hooks.
//
// Infrastructure whose only purpose is to shape target traffic is built on the
// strength of this. Session hydration in particular EXECUTES LOGIN FLOWS, so
// `vigolium run external-harvest --auth-file admin.yaml` used to authenticate
// against a host it was never going to touch.
func (p NativeScanPlan) SendsTargetTraffic() bool {
	for _, step := range p.Steps {
		if step.Enabled && !step.SkipsTarget {
			return true
		}
	}
	return false
}

// parseOnlyPhases parses a comma-separated --only value into a normalized
// set + ordered slice. Empty entries are skipped, duplicates collapse, and an
// unknown phase produces an error using the canonical phase list.
func parseOnlyPhases(raw string) (map[string]bool, []string, error) {
	parts := strings.Split(raw, ",")
	allowed := make(map[string]bool, len(parts))
	normalized := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n := NormalizeNativePhase(p)
		if !IsOnlyPhaseSpelling(n) {
			return nil, nil, fmt.Errorf("invalid --only value %q; valid phases: %s", p, ValidOnlyPhasesDesc)
		}
		if !allowed[n] {
			allowed[n] = true
			normalized = append(normalized, n)
		}
	}
	if len(allowed) == 0 {
		return nil, nil, fmt.Errorf("--only requires at least one phase; valid phases: %s", ValidOnlyPhasesDesc)
	}
	return allowed, normalized, nil
}

// OnlyPhaseSet returns the set of normalized phases listed in a comma-separated
// --only value. Callers use it to gate behavior that depends on which phases
// are active (e.g. validating that --format=html was scoped to phases that
// produce a report). Returns nil for empty input.
func OnlyPhaseSet(raw string) map[string]bool {
	if raw == "" {
		return nil
	}
	set := make(map[string]bool)
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		set[NormalizeNativePhase(p)] = true
	}
	return set
}

// NormalizeNativePhase maps every accepted spelling of a phase to its canonical
// id. Input is trimmed and lowercased first: --only already trimmed, --skip did
// not, so `--skip Discovery` (or ` discovery`) reached the switch verbatim, fell
// through to default, and was reported as an invalid phase. Aliases are extra
// surface for a driver to get subtly wrong; normalizing here means every caller
// — --only, --skip, `run <phase>`, the pace-flag qualifiers, and the
// scan.started event's canonical phase list — agrees on what a spelling means.
func NormalizeNativePhase(phase string) string {
	phase = strings.ToLower(strings.TrimSpace(phase))
	if canonical, ok := nativePhaseAliasIndex[phase]; ok {
		return canonical
	}
	return phase
}

// IsNativePhaseSpelling reports whether s names a native scan phase under any
// accepted spelling. Callers that need to branch on "is this a phase?" ask here
// rather than re-listing spellings, so a new alias reaches them for free.
func IsNativePhaseSpelling(s string) bool {
	_, ok := nativePhaseAliasIndex[strings.ToLower(strings.TrimSpace(s))]
	return ok
}

// lookupPhaseSpelling returns the vocabulary row a spelling resolves to.
func lookupPhaseSpelling(s string) (nativePhaseSpelling, bool) {
	canonical, ok := nativePhaseAliasIndex[strings.ToLower(strings.TrimSpace(s))]
	if !ok {
		return nativePhaseSpelling{}, false
	}
	for _, p := range nativePhaseVocabulary {
		if p.Canonical == canonical {
			return p, true
		}
	}
	return nativePhaseSpelling{}, false
}

// IsOnlyPhaseSpelling reports whether --only (and `run <phase>`) accepts s.
// Internal steps (seed, targeted-respider, preflight) are phase names but not
// runnable on their own.
func IsOnlyPhaseSpelling(s string) bool {
	p, ok := lookupPhaseSpelling(s)
	return ok && p.onlyAccepted()
}

// IsSkippablePhaseSpelling reports whether --skip accepts s.
func IsSkippablePhaseSpelling(s string) bool {
	p, ok := lookupPhaseSpelling(s)
	return ok && p.Skippable
}

// ApplyNativePhaseSelection resolves --only / --skip onto opts. setExtensions
// is how the caller's settings learn the extension decision: called with true
// when --only lists extension, false on --skip extension. It may be nil.
func ApplyNativePhaseSelection(opts *types.Options, setExtensions func(enabled bool)) error {
	if opts.OnlyPhase != "" && len(opts.SkipPhases) > 0 {
		return fmt.Errorf("--only and --skip are mutually exclusive; use one or the other")
	}

	for i := range opts.SkipPhases {
		opts.SkipPhases[i] = NormalizeNativePhase(opts.SkipPhases[i])
	}

	if opts.OnlyPhase != "" {
		allowed, normalized, err := parseOnlyPhases(opts.OnlyPhase)
		if err != nil {
			return err
		}
		opts.OnlyPhase = strings.Join(normalized, ",")

		opts.DiscoverEnabled = allowed["discovery"]
		opts.ExternalHarvestEnabled = allowed["external-harvest"]
		opts.SpideringEnabled = allowed["spidering"]
		opts.KnownIssueScanEnabled = allowed["known-issue-scan"]
		opts.ProbeEnabled = allowed["probe"]
		// "probe" is its own ingestion: it reads the CLI target list directly and
		// writes a record per target. Without this arm, --only probe would also
		// enable the discovery/ingestion phase (SkipIngestion is false unless BOTH
		// are absent) and every target would be fetched a second time.
		opts.SkipIngestion = !allowed["discovery"] && !allowed["ingestion"]
		opts.SkipDynamicAssessment = !allowed["dynamic-assessment"] && !allowed["extension"]
		if allowed["extension"] {
			// "extension" alone narrows dynamic-assessment to extension modules;
			// alongside "dynamic-assessment" it ADDS extensions to the built-ins.
			opts.ExtensionsOnly = !allowed["dynamic-assessment"]
			if setExtensions != nil {
				setExtensions(true)
			}
		}
		// The alternate-port sweep runs only when --only asked for it by name;
		// otherwise `--only dast --intensity deep` would still sweep ports.
		opts.SkipPortSweep = !allowed["port-sweep"]
		if allowed["heuristics-check"] {
			if opts.HeuristicsCheck == "" || opts.HeuristicsCheck == "none" {
				opts.HeuristicsCheck = "basic"
			}
		} else {
			opts.HeuristicsCheck = "none"
		}
	}

	applyProbeOnlyDefaults(opts)

	if len(opts.SkipPhases) > 0 {
		for _, phase := range opts.SkipPhases {
			switch phase {
			case "discovery", "ingestion":
				opts.SkipIngestion = true
				// Keep DiscoverEnabled in sync with the skip (mirrors the
				// --only path) so the config panel and downstream gates don't
				// still report discovery as active.
				opts.DiscoverEnabled = false
			case "external-harvest":
				opts.ExternalHarvestEnabled = false
			case "spidering":
				opts.SpideringEnabled = false
			case "probe":
				opts.ProbeEnabled = false
			case "known-issue-scan":
				opts.KnownIssueScanEnabled = false
			case "dynamic-assessment":
				opts.SkipDynamicAssessment = true
			case "extension":
				opts.ExtensionsOnly = false
				if setExtensions != nil {
					setExtensions(false)
				}
			case "heuristics-check":
				opts.HeuristicsCheck = "none"
			case "port-sweep":
				opts.SkipPortSweep = true
			case "targeted-respider":
				opts.SkipTargetedRespider = true
			case "preflight":
				opts.SkipPreflight = true
			default:
				return fmt.Errorf("invalid --skip value %q; valid phases: %s", phase, ValidSkipPhasesDesc)
			}
		}
	}

	return nil
}

// IsProbeOnlyRun reports whether this invocation is a standalone host sweep:
// `vigolium run probe`, `scan --only probe`, or REST {"only":"probe"}.
//
// The probe's own defaults apply only here. When the phase rides along inside a
// full scan, the scan's redirect and recording policy governs — silently
// swapping it out from under the other phases would be a surprise.
func IsProbeOnlyRun(opts *types.Options) bool {
	if opts == nil || !opts.ProbeEnabled {
		return false
	}
	only := OnlyPhaseSet(opts.OnlyPhase)
	return len(only) == 1 && only[string(PhaseProbe)]
}

// applyProbeOnlyDefaults gives a standalone host sweep the policy it wants.
//
// It lives HERE, inside ApplyNativePhaseSelection, because that is the one seam
// the CLI (pkg/cli/scan.go), the REST API (pkg/server/handlers_scan.go) and the
// programmatic launcher (internal/runner/launch.go) all pass through. Resolving
// it in the CLI instead — which is where it started — meant
// `POST /api/scan {"only":"probe"}` ran the same phase with a different redirect
// policy, no hop recording and the general-purpose transport: the same phase
// name doing materially different things depending on how it was started.
//
// Every default is applied only when the field is still unset, so an operator
// who asked for something else keeps it.
func applyProbeOnlyDefaults(opts *types.Options) {
	if !IsProbeOnlyRun(opts) {
		return
	}
	// A sweep is mostly redirects, and a chain collapsed into a single row is
	// the one thing that makes the output wrong rather than merely thin: the row
	// would carry the original URL against the final hop's body.
	if !opts.RecordRedirectChainSet {
		opts.RecordRedirectChain = true
	}
	// A host list is full of apex -> www and http -> https hops that are the
	// same application, while a hop to a different registrable domain is a
	// different party whose pages would otherwise be attributed to the target
	// that pointed at them.
	if opts.RedirectMode == "" {
		opts.RedirectMode = http.RedirectModeSameApex
	}
	// Retune the connection pool for many-hosts-one-request-each. Safe to set on
	// the shared options precisely BECAUSE this is a probe-only run: no other
	// phase will use this requester, so there is no active transport being
	// mutated out from under anyone and no second pool to pay for.
	if opts.TransportProfile == "" {
		opts.TransportProfile = http.TransportProfileSweep
	}
	// Proactive CDN/WAF-edge pacing is for a phase that is about to burst one
	// host with hundreds of requests. A sweep sends ONE request per host, so
	// there is no burst to pre-empt and nothing the throttle can protect — while
	// the costs are all still paid: PreArm flips the limiter's anyArmed flag, so
	// the first edge-fronted host switches adaptive feedback on for every host in
	// the run, and each one prints a "pacing per-host concurrency 40->10" notice
	// that is pure noise across thousands of targets. PreArmable() also gates the
	// per-response edge fingerprint, so turning this off removes that work too.
	//
	// Reactive back-off after an actual WAF block is untouched and still applies.
	if !opts.NoWafPacingSet {
		opts.NoWafPacing = true
	}
}
