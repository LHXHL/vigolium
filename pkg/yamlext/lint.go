package yamlext

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/types/severity"
)

// YAMLLintIssue represents a single lint finding for a YAML extension.
type YAMLLintIssue struct {
	Severity string // "error" or "warning"
	Line     int    // 1-based, 0 if unknown
	Col      int    // 1-based, 0 if unknown
	Message  string
	Rule     string // stable rule id, e.g. "yaml-unknown-key"
}

// YAMLLintResult holds the outcome of linting a single YAML extension file.
type YAMLLintResult struct {
	Path   string
	Issues []YAMLLintIssue
}

// HasErrors returns true if any issue is an error.
func (r *YAMLLintResult) HasErrors() bool {
	for _, i := range r.Issues {
		if i.Severity == "error" {
			return true
		}
	}
	return false
}

// reYAMLErrLine pulls the line out of a yaml.v3 error ("yaml: line 4: …").
var reYAMLErrLine = regexp.MustCompile(`line (\d+)`)

// LintYAML validates a YAML extension source string and returns any issues
// found. Unknown keys are errors here whatever extensions.yaml_strict says:
// lint is where a typo should be caught.
func LintYAML(source, filename string) *YAMLLintResult {
	result := &YAMLLintResult{Path: filename}

	// Phase 1: YAML parse check
	root, err := parseDocument([]byte(source))
	if err != nil {
		line := 0
		if m := reYAMLErrLine.FindStringSubmatch(err.Error()); m != nil {
			line, _ = strconv.Atoi(m[1])
		}
		result.Issues = append(result.Issues, YAMLLintIssue{
			Severity: "error", Line: line, Rule: "yaml-parse",
			Message: fmt.Sprintf("YAML parse error: %v", err),
		})
		return result
	}
	if root == nil {
		result.Issues = append(result.Issues, YAMLLintIssue{
			Severity: "error", Rule: "yaml-parse", Message: "file is empty",
		})
		return result
	}

	// Phase 2: unknown keys, with a suggestion and their position.
	schemaIssues, fieldLines := checkSchema(root)
	for _, si := range schemaIssues {
		result.Issues = append(result.Issues, YAMLLintIssue{
			Severity: "error", Line: si.Line, Col: si.Col, Rule: "yaml-unknown-key",
			Message: si.Message(),
		})
	}

	// Phase 3: Unmarshal into schema
	var def ExtensionDef
	if err := root.Decode(&def); err != nil {
		line := 0
		if m := reYAMLErrLine.FindStringSubmatch(err.Error()); m != nil {
			line, _ = strconv.Atoi(m[1])
		}
		result.Issues = append(result.Issues, YAMLLintIssue{
			Severity: "error", Line: line, Rule: "yaml-schema",
			Message: fmt.Sprintf("schema error: %v", err),
		})
		return result
	}
	at := func(path string) int { return lineOf(fieldLines, path) }

	// Phase 4: Required field validation
	if def.Type == "" {
		result.Issues = append(result.Issues, YAMLLintIssue{
			Severity: "error", Rule: "missing-type",
			Message: "missing required field 'type'",
		})
		return result // can't validate further without type
	}

	validTypes := map[string]bool{"active": true, "passive": true, "pre_hook": true, "post_hook": true}
	if !validTypes[def.Type] {
		result.Issues = append(result.Issues, YAMLLintIssue{
			Severity: "error", Line: at("type"), Rule: "invalid-type",
			Message: fmt.Sprintf("invalid type %q; must be one of: active, passive, pre_hook, post_hook", def.Type),
		})
		return result
	}

	// Phase 5: Type-specific validation
	switch def.Type {
	case "active":
		result.Issues = append(result.Issues, lintActiveYAML(&def, at)...)
	case "passive":
		result.Issues = append(result.Issues, lintPassiveYAML(&def, at)...)
	case "pre_hook":
		result.Issues = append(result.Issues, lintPreHookYAML(&def, at)...)
	case "post_hook":
		result.Issues = append(result.Issues, lintPostHookYAML(&def, at)...)
	}

	// Phase 6: Common validation
	result.Issues = append(result.Issues, lintCommonYAML(&def, at)...)

	return result
}

// lineOf returns the line of the key at path, or of its nearest present
// parent ("matchers[2].regex" falls back to "matchers"); 0 when none is known.
func lineOf(fieldLines map[string]int, path string) int {
	for path != "" {
		if l, ok := fieldLines[path]; ok {
			return l
		}
		if i := strings.LastIndexAny(path, ".["); i >= 0 {
			path = path[:i]
		} else {
			return 0
		}
	}
	return 0
}

// lintCommonYAML validates fields common to all YAML extension types.
func lintCommonYAML(def *ExtensionDef, at func(string) int) []YAMLLintIssue {
	var issues []YAMLLintIssue

	if def.ID == "" {
		issues = append(issues, YAMLLintIssue{
			Severity: "warning",
			Rule:     "missing-id",
			Message:  "missing 'id' field (will be auto-generated from filename)",
		})
	}

	// Validate severity
	if def.Severity != "" && !isValidYAMLSeverity(def.Severity) {
		issues = append(issues, YAMLLintIssue{
			Severity: "warning",
			Rule:     "bad-severity",
			Line:     at("severity"),
			Message:  fmt.Sprintf("unknown severity %q; expected one of: critical, high, medium, low, info, suspect", def.Severity),
		})
	}

	// Validate confidence
	if def.Confidence != "" {
		if !isValidYAMLConfidence(def.Confidence) {
			issues = append(issues, YAMLLintIssue{
				Severity: "error",
				Rule:     "bad-confidence",
				Line:     at("confidence"),
				Message:  fmt.Sprintf("unknown confidence %q; expected one of: tentative, firm, certain", def.Confidence),
			})
		}
	}
	if def.Finding != nil && !isValidYAMLConfidence(def.Finding.Confidence) {
		issues = append(issues, YAMLLintIssue{
			Severity: "error",
			Rule:     "bad-confidence",
			Line:     at("finding.confidence"),
			Message:  fmt.Sprintf("finding.confidence: unknown confidence %q; expected one of: tentative, firm, certain", def.Finding.Confidence),
		})
	}
	for i, rule := range def.Rules {
		if !isValidYAMLConfidence(rule.Finding.Confidence) {
			issues = append(issues, YAMLLintIssue{
				Severity: "error",
				Rule:     "bad-confidence",
				Line:     at(fmt.Sprintf("rules[%d].finding.confidence", i)),
				Message:  fmt.Sprintf("rules[%d].finding.confidence: unknown confidence %q; expected one of: tentative, firm, certain", i, rule.Finding.Confidence),
			})
		}
	}

	// Validate scan_types
	for _, st := range def.ScanTypes {
		if !isValidYAMLScanType(st) {
			issues = append(issues, YAMLLintIssue{
				Severity: "warning",
				Rule:     "bad-scan-type",
				Line:     at("scan_types"),
				Message:  fmt.Sprintf("unknown scan type %q; expected: per_insertion_point, per_request, per_host", st),
			})
		}
	}

	// Validate matchers_condition
	if def.MatchersCondition != "" && def.MatchersCondition != "or" && def.MatchersCondition != "and" {
		issues = append(issues, YAMLLintIssue{
			Severity: "warning",
			Rule:     "bad-matchers-condition",
			Line:     at("matchers_condition"),
			Message:  fmt.Sprintf("unknown matchers_condition %q; expected: or, and", def.MatchersCondition),
		})
	}

	// Validate regex patterns in matchers
	for i, m := range def.Matchers {
		if m.Regex != "" {
			if _, err := compileCached(m.Regex); err != nil {
				issues = append(issues, YAMLLintIssue{
					Severity: "error",
					Rule:     "bad-regex",
					Line:     at(fmt.Sprintf("matchers[%d].regex", i)),
					Message:  fmt.Sprintf("matchers[%d]: invalid regex %q: %v", i, m.Regex, err),
				})
			}
		}
		if m.Type != "" {
			validMatcherTypes := map[string]bool{"body": true, "header": true, "status": true, "js": true}
			if !validMatcherTypes[m.Type] {
				issues = append(issues, YAMLLintIssue{
					Severity: "warning",
					Rule:     "bad-matcher-type",
					Line:     at(fmt.Sprintf("matchers[%d].type", i)),
					Message:  fmt.Sprintf("matchers[%d]: unknown type %q; expected: body, header, status, js", i, m.Type),
				})
			}
		}
		if m.Type == "header" && m.Name == "" {
			issues = append(issues, YAMLLintIssue{
				Severity: "warning",
				Rule:     "matcher-missing-field",
				Line:     at(fmt.Sprintf("matchers[%d].type", i)),
				Message:  fmt.Sprintf("matchers[%d]: header matcher missing 'name' field", i),
			})
		}
		if m.Type == "status" && len(m.Codes) == 0 {
			issues = append(issues, YAMLLintIssue{
				Severity: "warning",
				Rule:     "matcher-missing-field",
				Line:     at(fmt.Sprintf("matchers[%d].type", i)),
				Message:  fmt.Sprintf("matchers[%d]: status matcher missing 'codes' field", i),
			})
		}
	}

	// Validate regex patterns in rules
	for i, rule := range def.Rules {
		if rule.Match.Regex != "" {
			if _, err := compileCached(rule.Match.Regex); err != nil {
				issues = append(issues, YAMLLintIssue{
					Severity: "error",
					Rule:     "bad-regex",
					Line:     at(fmt.Sprintf("rules[%d].match.regex", i)),
					Message:  fmt.Sprintf("rules[%d].match.regex: invalid regex %q: %v", i, rule.Match.Regex, err),
				})
			}
		}
		if rule.Match.BodyRegex != "" {
			if _, err := compileCached(rule.Match.BodyRegex); err != nil {
				issues = append(issues, YAMLLintIssue{
					Severity: "error",
					Rule:     "bad-regex",
					Line:     at(fmt.Sprintf("rules[%d].match.body_regex", i)),
					Message:  fmt.Sprintf("rules[%d].match.body_regex: invalid regex %q: %v", i, rule.Match.BodyRegex, err),
				})
			}
		}
	}

	return issues
}

// lintActiveYAML validates an active YAML extension.
func lintActiveYAML(def *ExtensionDef, at func(string) int) []YAMLLintIssue {
	var issues []YAMLLintIssue

	if def.Severity == "" {
		issues = append(issues, YAMLLintIssue{
			Severity: "warning",
			Rule:     "missing-severity",
			Message:  "active extension should declare a severity",
		})
	}

	// Active module needs payloads+matchers, or rules, or a script
	hasPayloads := len(def.Payloads) > 0
	hasMatchers := len(def.Matchers) > 0
	hasRules := len(def.Rules) > 0
	hasScript := def.Script != ""

	if !hasPayloads && !hasRules && !hasScript {
		issues = append(issues, YAMLLintIssue{
			Severity: "warning",
			Rule:     "no-effect",
			Message:  "active extension has no payloads, rules, or script — it won't generate any findings",
		})
	}

	// Payloads are only sent by ScanPerInsertionPoint, which runs only when
	// scan_types includes per_insertion_point (the default is per_request).
	if hasPayloads && !hasScanType(def.ScanTypes, "per_insertion_point") {
		issues = append(issues, YAMLLintIssue{
			Severity: "warning",
			Rule:     "payloads-unused",
			Line:     at("payloads"),
			Message:  "payloads are only used by per_insertion_point; add it to scan_types",
		})
	}

	if hasPayloads && !hasMatchers && !hasRules {
		issues = append(issues, YAMLLintIssue{
			Severity: "warning",
			Rule:     "no-matchers",
			Line:     at("payloads"),
			Message:  "active extension has payloads but no matchers or rules to check responses",
		})
	}

	return issues
}

// lintPassiveYAML validates a passive YAML extension.
func lintPassiveYAML(def *ExtensionDef, at func(string) int) []YAMLLintIssue {
	var issues []YAMLLintIssue

	if def.Scope != "" {
		validScopes := map[string]bool{"request": true, "response": true, "both": true}
		if !validScopes[def.Scope] {
			issues = append(issues, YAMLLintIssue{
				Severity: "warning",
				Rule:     "bad-scope",
				Line:     at("scope"),
				Message:  fmt.Sprintf("unknown scope %q; expected: request, response, both", def.Scope),
			})
		}
	}

	// Passive needs matchers or rules or a script
	if len(def.Matchers) == 0 && len(def.Rules) == 0 && def.Script == "" {
		issues = append(issues, YAMLLintIssue{
			Severity: "warning",
			Rule:     "no-effect",
			Message:  "passive extension has no matchers, rules, or script — it won't generate any findings",
		})
	}

	return issues
}

// lintPreHookYAML validates a pre_hook YAML extension.
func lintPreHookYAML(def *ExtensionDef, at func(string) int) []YAMLLintIssue {
	var issues []YAMLLintIssue

	if len(def.AddHeaders) == 0 && len(def.SkipExtensions) == 0 && def.Script == "" {
		issues = append(issues, YAMLLintIssue{
			Severity: "warning",
			Rule:     "no-effect",
			Message:  "pre_hook has no add_headers, skip_extensions, or script — it won't do anything",
		})
	}

	return issues
}

// lintPostHookYAML validates a post_hook YAML extension.
func lintPostHookYAML(def *ExtensionDef, at func(string) int) []YAMLLintIssue {
	var issues []YAMLLintIssue

	if def.Escalate == nil && def.DropWhen == nil && def.Script == "" {
		issues = append(issues, YAMLLintIssue{
			Severity: "warning",
			Rule:     "no-effect",
			Message:  "post_hook has no escalate, drop_when, or script — it won't do anything",
		})
	}

	if def.Escalate != nil && len(def.Escalate.WhenURLContains) == 0 {
		issues = append(issues, YAMLLintIssue{
			Severity: "warning",
			Rule:     "no-effect",
			Line:     at("escalate"),
			Message:  "escalate has no when_url_contains patterns — it will never trigger",
		})
	}

	if def.DropWhen != nil && len(def.DropWhen.Severity) == 0 && len(def.DropWhen.URLContains) == 0 {
		issues = append(issues, YAMLLintIssue{
			Severity: "warning",
			Rule:     "no-effect",
			Line:     at("drop_when"),
			Message:  "drop_when has no severity or url_contains conditions — it will never trigger",
		})
	}

	return issues
}

// hasScanType reports whether scanTypes names want (the empty list means the
// per_request default).
func hasScanType(scanTypes []string, want string) bool {
	for _, st := range scanTypes {
		if strings.EqualFold(strings.TrimSpace(st), want) {
			return true
		}
	}
	return false
}

func isValidYAMLSeverity(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "high", "medium", "low", "info", "suspect":
		return true
	}
	return false
}

func isValidYAMLScanType(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "per_insertion_point", "per_request", "per_host":
		return true
	}
	return false
}

// isValidYAMLConfidence reports whether s is empty (module default applies)
// or one of tentative, firm, certain.
func isValidYAMLConfidence(s string) bool {
	return strings.TrimSpace(s) == "" || severity.ToConfidence(s) != severity.ConfidenceUndefined
}
