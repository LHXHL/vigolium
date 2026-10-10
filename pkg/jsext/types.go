package jsext

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// ScriptType identifies the kind of JS extension.
type ScriptType string

const (
	ScriptTypeActive   ScriptType = "active"
	ScriptTypePassive  ScriptType = "passive"
	ScriptTypePreHook  ScriptType = "pre_hook"
	ScriptTypePostHook ScriptType = "post_hook"
)

// ScriptMetadata holds parsed metadata from a JS module.exports.
type ScriptMetadata struct {
	ID                   string     `json:"id"`
	Name                 string     `json:"name"`
	Severity             string     `json:"severity"`
	Confidence           string     `json:"confidence"` // tentative, firm, certain
	Type                 ScriptType `json:"type"`
	ScanTypes            []string   `json:"scanTypes"` // for active: per_insertion_point, per_request, per_host
	Scope                string     `json:"scope"`     // for passive: request, response, both
	Description          string     `json:"description"`
	ConfirmationCriteria string     `json:"confirmationCriteria"`
	Tags                 []string   `json:"tags"`
}

// LoadedScript holds a compiled script and its metadata.
type LoadedScript struct {
	Path     string
	Source   string
	Metadata ScriptMetadata
	// Explicit says the script was named directly (--ext or
	// extensions.custom_dir) rather than found in the extension directory.
	Explicit bool
}

// ParseSeverity converts a string severity to the severity type.
func ParseSeverity(s string) severity.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return severity.Critical
	case "high":
		return severity.High
	case "medium":
		return severity.Medium
	case "low":
		return severity.Low
	case "suspect":
		return severity.Suspect
	case "info":
		return severity.Info
	default:
		return severity.Info
	}
}

// ParseConfidence converts a confidence string (tentative, firm, certain) to
// the severity type, returning def when s is empty or unrecognized. Shared by
// the JS and YAML extension loaders so module defaults and per-result values
// parse identically.
func ParseConfidence(s string, def severity.Confidence) severity.Confidence {
	if c := severity.ToConfidence(s); c != severity.ConfidenceUndefined {
		return c
	}
	return def
}

// IsValidConfidence reports whether s is a recognized confidence value.
// An empty string is valid (the module default applies).
func IsValidConfidence(s string) bool {
	return strings.TrimSpace(s) == "" || severity.ToConfidence(s) != severity.ConfidenceUndefined
}

// ParseScanScopes converts string scan types to bitmask.
func ParseScanScopes(types []string) modkit.ScanScope {
	var result modkit.ScanScope
	for _, t := range types {
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "per_insertion_point":
			result |= modkit.ScanScopeInsertionPoint
		case "per_request":
			result |= modkit.ScanScopeRequest
		case "per_host":
			result |= modkit.ScanScopeHost
		}
	}
	if result == 0 {
		result = modkit.ScanScopeRequest
	}
	return result
}

// ParsePassiveScope converts a string scope to PassiveScanScope.
func ParsePassiveScope(s string) modkit.PassiveScanScope {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "request":
		return modkit.PassiveScanScopeRequest
	case "response":
		return modkit.PassiveScanScopeResponse
	default:
		return modkit.PassiveScanScopeBoth
	}
}
