package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// filterSummary accumulates colored "key=value" fragments describing the filter
// conditions in effect, for the "Filtered by:" echo shared by the finding and
// traffic listings. Empty values are dropped so callers can add
// unconditionally; call print() to emit the line (or nothing when no filter is
// set).
//
// Color scheme: cyan label, gray '=', bold value — except severity/confidence
// values, which are colored by their conventional level color.
type filterSummary struct {
	parts []string
}

// push appends a "label=value" fragment with the shared label/separator colors
// and an already-colored value.
func (s *filterSummary) push(label, coloredVal string) {
	s.parts = append(s.parts, terminal.Cyan(label)+terminal.Gray("=")+coloredVal)
}

// add appends "label=val" (value bolded) unless val is empty.
func (s *filterSummary) add(label, val string) {
	if val == "" {
		return
	}
	s.push(label, terminal.Bold(val))
}

// addQuoted appends "label=\"val\"" unless val is empty, so free-text search
// terms read clearly (and any embedded separators can't be mistaken for more
// fields).
func (s *filterSummary) addQuoted(label, val string) {
	if val == "" {
		return
	}
	s.push(label, terminal.Bold(strconv.Quote(val)))
}

// addInts appends "label=v1,v2,…" (each value bolded) unless vals is empty.
func (s *filterSummary) addInts(label string, vals []int) {
	if len(vals) == 0 {
		return
	}
	strs := make([]string, len(vals))
	for i, v := range vals {
		strs[i] = terminal.Bold(strconv.Itoa(v))
	}
	s.push(label, strings.Join(strs, terminal.Gray(",")))
}

// addSeverities appends a severity filter, coloring each level token by its
// conventional severity color (medium→yellow, info→blue, critical→magenta, …).
func (s *filterSummary) addSeverities(label string, sevs []string) {
	if len(sevs) == 0 {
		return
	}
	colored := make([]string, len(sevs))
	for i, sev := range sevs {
		colored[i] = clicommon.ColorSeverity(sev)
	}
	s.push(label, strings.Join(colored, terminal.Gray(",")))
}

// addMinSeverity appends a --min-severity filter as "<threshold> (<expanded>)",
// coloring the threshold and each expanded level by its severity color so it's
// clear which levels the threshold covers (and that a fuzzy token resolved).
func (s *filterSummary) addMinSeverity(label, threshold string, expanded []string) {
	if threshold == "" {
		return
	}
	colored := make([]string, len(expanded))
	for i, sev := range expanded {
		colored[i] = clicommon.ColorSeverity(sev)
	}
	val := clicommon.ColorSeverity(threshold) +
		terminal.Gray(" (") + strings.Join(colored, terminal.Gray(",")) + terminal.Gray(")")
	s.push(label, val)
}

// addConfidences appends a confidence filter, coloring each level by its
// conventional color (certain→purple, firm→yellow, tentative→gray).
func (s *filterSummary) addConfidences(label string, confs []string) {
	if len(confs) == 0 {
		return
	}
	colored := make([]string, len(confs))
	for i, c := range confs {
		colored[i] = clicommon.ColorConfidence(c)
	}
	s.push(label, strings.Join(colored, terminal.Gray(",")))
}

// String renders just the joined fragments, for a caller that needs the summary
// inside its own line (the `db clean` preview writes it to stderr under an
// indented "Filters:" label) rather than as the standalone "Filtered by:" line.
func (s *filterSummary) String() string {
	return strings.Join(s.parts, terminal.Gray(" · "))
}

// print emits the "Filtered by:" line to stdout, or nothing when no filter is
// set. Callers gate this on text-mode output — JSON must stay clean on stdout.
func (s *filterSummary) print() {
	if len(s.parts) == 0 {
		return
	}
	fmt.Printf("%s %s %s\n",
		terminal.InfoSymbol(),
		terminal.Bold("Filtered by:"),
		s.String())
}
