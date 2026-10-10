package output

import (
	"encoding/xml"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/types/severity"
)

// DefaultJUnitFailOn is the failure threshold when the caller sets none (no
// --fail-on): low and above fail, info and suspect findings are listed in the
// testcase's system-out without failing it.
const DefaultJUnitFailOn = "low"

// DismissedFindingStatuses are the statuses whose findings never fail a gate:
// an operator ruled them not a bug or accepted the risk. Mirrors
// database.DismissedFindingStatuses (pkg/database imports this package, so it
// cannot be referenced directly; a pkg/cli test keeps the two equal).
var DismissedFindingStatuses = []string{"false_positive", "accepted_risk"}

func isDismissedStatus(status string) bool {
	return slices.Contains(DismissedFindingStatuses, strings.ToLower(strings.TrimSpace(status)))
}

type junitTestSuites struct {
	XMLName  xml.Name         `xml:"testsuites"`
	Name     string           `xml:"name,attr"`
	Tests    int              `xml:"tests,attr"`
	Failures int              `xml:"failures,attr"`
	Errors   int              `xml:"errors,attr"`
	Skipped  int              `xml:"skipped,attr"`
	Time     string           `xml:"time,attr"`
	Suites   []junitTestSuite `xml:"testsuite"`
}

type junitTestSuite struct {
	Name       string          `xml:"name,attr"`
	Tests      int             `xml:"tests,attr"`
	Failures   int             `xml:"failures,attr"`
	Errors     int             `xml:"errors,attr"`
	Skipped    int             `xml:"skipped,attr"`
	Time       string          `xml:"time,attr"`
	Properties []junitProperty `xml:"properties>property,omitempty"`
	Cases      []junitTestCase `xml:"testcase"`
}

type junitProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

type junitTestCase struct {
	Name      string         `xml:"name,attr"`
	ClassName string         `xml:"classname,attr"`
	Time      string         `xml:"time,attr"`
	Failures  []junitFailure `xml:"failure"`
	Skipped   *junitSkipped  `xml:"skipped"`
	SystemOut string         `xml:"system-out,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

type junitSkipped struct {
	Message string `xml:"message,attr"`
}

// GenerateJUnitReport writes the findings as JUnit XML for CI test reporters:
// one <testsuite> per module, one <testcase> per (module, host), and one
// <failure> per finding at or above meta.FailOn (DefaultJUnitFailOn when
// empty). Findings below the threshold are listed in the testcase's
// system-out; a testcase whose findings are all dismissed (false_positive,
// accepted_risk) is <skipped>. Names are module IDs and hosts and every
// failure carries its finding_hash, so a CI history tracks the same finding
// across runs; ordering is deterministic.
func GenerateJUnitReport(items []any, outputPath string, meta HTMLReportMeta) error {
	doc := buildJUnitReport(collectFindingViews(items), meta)
	return writeReportFile(outputPath, func(w io.Writer) error {
		return writeJUnitXML(w, doc)
	})
}

func writeJUnitXML(w io.Writer, doc junitTestSuites) error {
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}

func junitThreshold(failOn string) (string, severity.Severity) {
	name := strings.ToLower(strings.TrimSpace(failOn))
	if severity.ToSeverity(name) == severity.Undefined {
		name = DefaultJUnitFailOn
	}
	return name, severity.ToSeverity(name)
}

func buildJUnitReport(findings []FindingView, meta HTMLReportMeta) junitTestSuites {
	thresholdName, threshold := junitThreshold(meta.FailOn)
	title := meta.Title
	if title == "" {
		title = defaultReportTitle
	}

	type caseKey struct{ module, host string }
	byCase := map[caseKey][]FindingView{}
	for _, f := range findings {
		module := f.ModuleID
		if module == "" {
			module = "unknown-module"
		}
		host := f.GroupHost()
		if host == "" {
			host = "(no host)"
		}
		k := caseKey{module, host}
		byCase[k] = append(byCase[k], f)
	}
	keys := make([]caseKey, 0, len(byCase))
	for k := range byCase {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].module != keys[j].module {
			return keys[i].module < keys[j].module
		}
		return keys[i].host < keys[j].host
	})

	doc := junitTestSuites{Name: title, Time: "0"}
	var suite *junitTestSuite
	for _, k := range keys {
		if suite == nil || suite.Name != k.module {
			doc.Suites = append(doc.Suites, junitTestSuite{
				Name:       k.module,
				Time:       "0",
				Properties: []junitProperty{{Name: "fail_on", Value: thresholdName}},
			})
			suite = &doc.Suites[len(doc.Suites)-1]
		}
		tc := buildJUnitCase(k.module, k.host, byCase[k], threshold)
		suite.Cases = append(suite.Cases, tc)
		suite.Tests++
		doc.Tests++
		if len(tc.Failures) > 0 {
			suite.Failures++
			doc.Failures++
		} else if tc.Skipped != nil {
			suite.Skipped++
			doc.Skipped++
		}
	}
	return doc
}

func buildJUnitCase(module, host string, findings []FindingView, threshold severity.Severity) junitTestCase {
	// Most severe first, then by hash, so the order is stable across runs.
	sort.SliceStable(findings, func(i, j int) bool {
		si, sj := severity.ToSeverity(findings[i].Severity), severity.ToSeverity(findings[j].Severity)
		if si != sj {
			return si > sj
		}
		return findings[i].FindingHash < findings[j].FindingHash
	})
	tc := junitTestCase{Name: host, ClassName: module, Time: "0"}
	var out []string
	dismissed := 0
	for _, f := range findings {
		switch {
		case isDismissedStatus(f.Status):
			dismissed++
			out = append(out, junitFindingLine(f)+" [status "+f.Status+"]")
		case severity.ToSeverity(f.Severity) >= threshold:
			tc.Failures = append(tc.Failures, junitFailure{
				Message: junitFindingLine(f),
				Type:    f.Severity,
				Body:    junitFailureBody(f),
			})
		default:
			out = append(out, junitFindingLine(f)+" [below threshold]")
		}
	}
	if len(tc.Failures) == 0 && dismissed == len(findings) {
		tc.Skipped = &junitSkipped{Message: fmt.Sprintf("%d dismissed finding(s)", dismissed)}
	}
	if len(out) > 0 {
		tc.SystemOut = strings.Join(out, "\n")
	}
	return tc
}

// junitFindingLine is the one-line identity of a finding: severity, name,
// location and the finding_hash prefix that names it across databases.
func junitFindingLine(f FindingView) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] %s", f.Severity, f.Name())
	if loc := f.Location(); loc != "" {
		b.WriteString(" at ")
		b.WriteString(loc)
	}
	if f.FindingHash != "" {
		fmt.Fprintf(&b, " (finding_hash %s)", shortHash(f.FindingHash))
	}
	return b.String()
}

// junitFailureBody lists the finding's identity as key: value lines, keyed by
// the finding view's JSON keys (`vigolium finding -j`).
func junitFailureBody(f FindingView) string {
	var lines []string
	add := func(k, v string) {
		if v != "" {
			lines = append(lines, k+": "+v)
		}
	}
	if f.ID > 0 {
		add("id", strconv.FormatInt(f.ID, 10))
	}
	add("finding_hash", f.FindingHash)
	add("severity", f.Severity)
	add("confidence", f.Confidence)
	add("module_id", f.ModuleID)
	add("url", f.URL)
	add("hostname", f.Hostname)
	add("source_file", f.SourceFile)
	add("matched_at", strings.Join(f.MatchedAt, ", "))
	add("scan_uuid", f.ScanUUID)
	add("http_record_uuids", strings.Join(f.HTTPRecordUUIDs, ", "))
	add("status", f.Status)
	add("cwe_id", f.CWEID)
	return strings.Join(lines, "\n")
}

// shortHash is the 12-character finding_hash prefix — the shortest prefix
// `vigolium finding mark` accepts, so the printed handle is directly usable.
func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
