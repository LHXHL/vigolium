package fuzz

import (
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// Anomaly detection answers the question explicit matchers make you answer
// yourself: "which of these responses is worth looking at?"
//
// Writing matchers requires knowing the answer in advance — you have to
// already know the interesting size, or the status the app returns when a
// payload lands. The detector instead scores each response against two
// references:
//
//	the baseline  — the un-fuzzed request's own response, and
//	the population — every other response in this same run.
//
// The population reference is what makes it work on an unknown target. If 400
// payloads produce the same 200/4kB page and one produces a 500, that one is
// interesting no matter what the numbers are. Conversely a status change that
// *every* payload triggers is the endpoint's normal behaviour, not a signal —
// and rarity is the only way to tell those apart.
//
// It emits scores and reasons, never verdicts: a high score means "look here",
// not "this is a vulnerability". That keeps fuzz a primitive.

// Anomaly severity thresholds. A single strong signal (an error signature, a
// server error) clears Medium on its own; weak signals have to stack.
const (
	AnomalyThresholdLow    = 25
	AnomalyThresholdMedium = 45
	AnomalyThresholdHigh   = 70
)

// ParseAnomalyThreshold maps a named level, or a bare number, to a score.
func ParseAnomalyThreshold(s string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "medium", "med":
		return AnomalyThresholdMedium, true
	case "low":
		return AnomalyThresholdLow, true
	case "high":
		return AnomalyThresholdHigh, true
	}
	return 0, false
}

// errorSignatures are strings that appear in a response only when something
// went wrong *inside* the application — a leaked driver error, a stack trace, a
// template engine complaining. Their appearance in a payload's response when
// the baseline had none is the single highest-value fuzzing signal there is,
// which is why it alone clears the Medium threshold.
// Database errors are deliberately absent here: modkit.BodyHasSQLError is the
// repo's single source of truth for those, and its own history records partial
// copies drifting until one of them hid a real SQLi. firstErrorSignature calls
// it rather than restating a weaker subset.
var errorSignatures = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bstack trace\b|\bTraceback \(most recent call last\)|\bat [\w.$]+\([\w.]+\.java:\d+\)`),
	regexp.MustCompile(`(?i)\bFatal error\b|\bWarning: \w+\(\)|\bUncaught \w*Exception|\bNoMethodError\b`),
	regexp.MustCompile(`(?i)\bSystem\.\w+Exception\b|\bJinja2?\b.{0,40}\berror|\bTemplateSyntaxError`),
	regexp.MustCompile(`(?i)\bjava\.lang\.\w+Exception|\bpanic: runtime error|\bgoroutine \d+ \[`),
	regexp.MustCompile(`(?i)failed to open stream|include\(\)|require_once\(|\bno such file or directory\b`),
}

// interestingHeaders are response headers whose appearance or change signals a
// different code path was taken — a redirect target, a new session, an auth
// challenge.
var interestingHeaders = []string{
	"Location", "Set-Cookie", "WWW-Authenticate", "Content-Type",
	"X-Powered-By", "Server", "Content-Disposition",
}

// AnomalyConfig controls detection.
type AnomalyConfig struct {
	// Threshold is the score at or above which a result is reported.
	Threshold int
	// MinPopulation is how many results must be seen before population-based
	// signals (rarity, outliers) are trusted. Below it, only baseline-relative
	// signals contribute — a "rare" status among four samples means nothing.
	MinPopulation int
}

// DefaultAnomalyConfig returns detection tuned for a typical run.
func DefaultAnomalyConfig() AnomalyConfig {
	return AnomalyConfig{Threshold: AnomalyThresholdMedium, MinPopulation: 12}
}

// AnomalyReason is one contributing signal.
type AnomalyReason struct {
	Signal string `json:"signal"`
	Detail string `json:"detail,omitempty"`
	Weight int    `json:"weight"`
}

// detector accumulates the population model and scores results against it.
//
// Scoring happens in two passes. The streaming pass scores what it can as
// results arrive; the population is still forming, so its verdict is
// provisional. Finalize then rescores everything against the complete
// population, which is what the summary reports. Without the second pass the
// first hundred results would be judged against statistics that hadn't
// converged, and on a run where the anomaly comes early that's exactly the
// result that would be missed.
type detector struct {
	cfg  AnomalyConfig
	base Baseline

	mu sync.Mutex

	total       int
	statusCount map[int]int
	hashCount   map[string]int
	lengths     []int64
	times       []int64

	baseHasError bool
	baseHeaders  http.Header
}

// popStats is the population model frozen at a point in time. Scoring reads a
// snapshot rather than the live model so the medians are computed once per
// pass instead of once per response: sorting the length and time samples is
// O(N log N), and doing it inside every score() call made the run O(N² log N)
// with an O(N) copy held under the lock each time.
//
// It carries only scalars. The status and body-hash tallies stay behind the
// detector's lock and are read per result by countsFor: handing out the live
// maps let a scoring goroutine read one while another worker's observe wrote
// it, and copying them per result would restore the O(N²) the snapshot exists
// to avoid.
type popStats struct {
	total          int
	distinctHashes int

	lenMed, lenMAD   int64
	timeMed, timeMAD int64
	haveSpread       bool
}

func newDetector(cfg AnomalyConfig, base Baseline, baseHeaders http.Header, baseBody []byte) *detector {
	if cfg.Threshold <= 0 {
		cfg.Threshold = AnomalyThresholdMedium
	}
	if cfg.MinPopulation <= 0 {
		cfg.MinPopulation = DefaultAnomalyConfig().MinPopulation
	}
	d := &detector{
		cfg:         cfg,
		base:        base,
		statusCount: make(map[int]int),
		hashCount:   make(map[string]int),
		baseHeaders: baseHeaders,
	}
	_, d.baseHasError = firstErrorSignature(baseBody)
	return d
}

// observe folds one result into the population model.
func (d *detector) observe(r *Result) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.total++
	if r.Error != "" {
		return
	}
	d.statusCount[r.Status]++
	if r.ContentHash != "" {
		d.hashCount[r.ContentHash]++
	}
	d.lengths = append(d.lengths, int64(r.Length))
	d.times = append(d.times, r.TimeMs)
}

// countsFor reports how many observed responses share this result's status and
// body hash. Both tallies are read under the lock because the streaming pass
// scores a result while other workers are still folding theirs in.
func (d *detector) countsFor(r *Result) (statusN, hashN int) {
	if d == nil {
		return 0, 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if r.ContentHash == "" {
		return d.statusCount[r.Status], 0
	}
	return d.statusCount[r.Status], d.hashCount[r.ContentHash]
}

// snapshot freezes the population model. withSpread additionally computes the
// median/MAD pair, which needs a sort — the streaming pass skips it (its
// verdict is provisional anyway) and the final rescore pass pays for it once.
func (d *detector) snapshot(withSpread bool) popStats {
	if d == nil {
		return popStats{}
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	ps := popStats{
		total:          d.total,
		distinctHashes: len(d.hashCount),
	}
	if !withSpread {
		return ps
	}
	lenMed, lenMAD, lenOK := medianAbsDev(d.lengths)
	timeMed, timeMAD, timeOK := medianAbsDev(d.times)
	ps.lenMed, ps.lenMAD = lenMed, lenMAD
	ps.timeMed, ps.timeMAD = timeMed, timeMAD
	ps.haveSpread = lenOK && timeOK
	return ps
}

// score computes the anomaly score and its reasons for one result.
// baselineSignals scores everything that compares a response to the *baseline*
// — which is fully determined the moment the response arrives. Computing it
// once in the worker means the response body and headers never have to be
// retained for a second pass.
func (d *detector) baselineSignals(r *Result, body []byte, headers http.Header) (int, []AnomalyReason) {
	if d == nil {
		return 0, nil
	}
	var (
		score   int
		reasons []AnomalyReason
	)
	add := func(signal, detail string, weight int) {
		score += weight
		reasons = append(reasons, AnomalyReason{Signal: signal, Detail: detail, Weight: weight})
	}

	// A transport error where the baseline succeeded: the payload broke
	// something at the connection level (a timeout, a reset, a malformed
	// response), which is itself a finding-shaped signal.
	if r.Error != "" {
		if d.base.Error == "" {
			add("transport_error", r.Error, 35)
		}
		return score, reasons
	}

	if r.Status != d.base.Status {
		switch {
		case r.Status >= 500:
			add("server_error", statusDetail(d.base.Status, r.Status), 40)
		case d.base.Status >= 400 && r.Status >= 200 && r.Status < 300:
			// Denied → allowed is the shape of an auth or access-control
			// bypass, and is worth more than an arbitrary status change.
			add("status_now_ok", statusDetail(d.base.Status, r.Status), 40)
		case r.Status >= 300 && r.Status < 400:
			add("status_redirect", statusDetail(d.base.Status, r.Status), 20)
		default:
			add("status_changed", statusDetail(d.base.Status, r.Status), 20)
		}
	}

	if !d.baseHasError {
		if match, ok := firstErrorSignature(body); ok {
			add("error_signature", truncateDetail(match), 45)
		}
	}

	if r.Reflected {
		if r.ReflectedRaw {
			add("reflected_unencoded", "payload appears verbatim in the response", 20)
		} else {
			add("reflected_encoded", "payload appears escaped/encoded in the response", 5)
		}
	}

	for _, name := range interestingHeaders {
		got, was := headers.Get(name), ""
		if d.baseHeaders != nil {
			was = d.baseHeaders.Get(name)
		}
		if got == was {
			continue
		}
		weight := 15
		if name == "Location" || name == "WWW-Authenticate" {
			weight = 25
		}
		add("header_changed", name+": "+truncateDetail(was)+" → "+truncateDetail(got), weight)
	}

	return score, reasons
}

// populationSignals scores a response against the rest of the run. Every input
// it needs is already a field of Result, so it can be recomputed after the run
// without holding on to any response bodies.
func (d *detector) populationSignals(r *Result, ps popStats) (int, []AnomalyReason) {
	if d == nil || r.Error != "" || ps.total < d.cfg.MinPopulation {
		return 0, nil
	}
	var (
		score   int
		reasons []AnomalyReason
	)
	add := func(signal, detail string, weight int) {
		score += weight
		reasons = append(reasons, AnomalyReason{Signal: signal, Detail: detail, Weight: weight})
	}

	statusN, hashN := d.countsFor(r)

	// A status almost nothing else returned.
	if statusN > 0 && rarity(statusN, ps.total) {
		add("rare_status", statusRarityDetail(r.Status, statusN, ps.total), 25)
	}
	// A body nothing else produced, on a run where bodies otherwise repeat.
	if r.ContentHash != "" && hashN == 1 && ps.distinctHashes < ps.total/2 {
		add("unique_body", "no other payload produced this response body", 30)
	}
	if !ps.haveSpread {
		return score, reasons
	}
	switch {
	case ps.lenMAD > 0:
		if absInt64(int64(r.Length)-ps.lenMed)/ps.lenMAD >= 6 {
			add("size_outlier", "length deviates far from the run's median", 30)
		}
	case int64(r.Length) != ps.lenMed:
		// Every other response was the same size; this one isn't.
		add("size_outlier", "only response whose length differs from the run", 30)
	}
	if ps.timeMAD > 0 && r.TimeMs > 500 && absInt64(r.TimeMs-ps.timeMed)/ps.timeMAD >= 6 {
		add("time_outlier", "response time far above the run's median", 25)
	}
	return score, reasons
}

// rarity reports whether n out of total is rare enough to be interesting:
// under 5% of the population, and never when it's the majority behaviour.
func rarity(n, total int) bool {
	return n*20 <= total
}

// medianAbsDev returns the median and median-absolute-deviation of vs. MAD is
// used rather than a standard deviation because a fuzz population is full of
// outliers by construction, and they would inflate a stddev enough to hide
// themselves.
func medianAbsDev(vs []int64) (median, mad int64, ok bool) {
	if len(vs) < 3 {
		return 0, 0, false
	}
	sorted := append([]int64(nil), vs...)
	slices.Sort(sorted)
	median = sorted[len(sorted)/2]

	devs := make([]int64, len(sorted))
	for i, v := range sorted {
		devs[i] = absInt64(v - median)
	}
	slices.Sort(devs)
	return median, devs[len(devs)/2], true
}

func absInt64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// firstErrorSignature returns the first application-error string found in body.
// One pass, returning the match: a separate "does it match" then "what
// matched" pair re-scanned the whole body with all six patterns a second time.
func firstErrorSignature(body []byte) (string, bool) {
	if len(body) == 0 {
		return "", false
	}
	// modkit owns the DBMS catalog; MatchSQLError also applies its
	// span guard, which a bare regex match would skip.
	if backend, re, ok := modkit.MatchSQLError(string(body)); ok {
		if m := re.Find(body); m != nil {
			return backend + " error: " + string(m), true
		}
		return backend + " error", true
	}
	for _, re := range errorSignatures {
		if m := re.Find(body); m != nil {
			return string(m), true
		}
	}
	return "", false
}

func truncateDetail(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	const limit = 80
	if len(s) > limit {
		return s[:limit] + "..."
	}
	if s == "" {
		return "(absent)"
	}
	return s
}

func statusDetail(from, to int) string {
	return strconv.Itoa(from) + " → " + strconv.Itoa(to)
}

func statusRarityDetail(status, n, total int) string {
	return fmt.Sprintf("%d seen in %d/%d responses", status, n, total)
}
