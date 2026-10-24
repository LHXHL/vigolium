package powerpages

import (
	"encoding/json"
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/infra/saasprobe"
)

// bogusEntitySet is an entity-set name that cannot exist on any Dataverse
// instance, used as the negative control / API-presence probe.
const bogusEntitySet = "vigolium_nonexistent_probe_sets"

// ODataList is the shape of a successful Dataverse Web API collection read.
type ODataList struct {
	Context string            `json:"@odata.context"`
	Count   *int              `json:"@odata.count"`
	Value   []json.RawMessage `json:"value"`
	Error   *odataError       `json:"error"`
}

// odataError is the Dataverse error envelope returned on 4xx/5xx.
type odataError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	CDSCode    string `json:"cdscode"`
	InnerError struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"innererror"`
}

// parseODataList unmarshals an OData collection response. ok is false when the
// body is not JSON at all (e.g. an HTML page), so callers can distinguish "not a
// Dataverse response" from "an empty Dataverse collection".
func parseODataList(body string) (ODataList, bool) {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" || trimmed[0] != '{' {
		return ODataList{}, false
	}
	var l ODataList
	if err := json.Unmarshal([]byte(trimmed), &l); err != nil {
		return ODataList{}, false
	}
	return l, true
}

// isDataverseNotFound reports whether a probe result is a Dataverse "resource
// does not exist for this segment" error — the signature of the /_api/ router
// rejecting an unknown entity set. Used as the API-presence gate and per-table
// negative control.
func isDataverseNotFound(res saasprobe.Result) bool {
	if res.Status != 404 && res.Status != 400 {
		return false
	}
	l, ok := parseODataList(res.Body)
	if !ok || l.Error == nil {
		// Fall back to a raw-text match for the canonical Dataverse messages, in
		// case the envelope shape drifts across versions.
		lower := strings.ToLower(res.Body)
		return strings.Contains(lower, "resource not found for the segment") ||
			strings.Contains(lower, "9004010c")
	}
	blob := strings.ToLower(l.Error.Code + " " + l.Error.Message + " " +
		l.Error.CDSCode + " " + l.Error.InnerError.Code + " " + l.Error.InnerError.Message)
	return strings.Contains(blob, "resource not found for the segment") ||
		strings.Contains(blob, "9004010c") ||
		strings.Contains(blob, "resourcedoesnotexists")
}

// VerdictKind classifies a /_api/<table> read.
type VerdictKind int

const (
	VerdictNone             VerdictKind = iota // 404 (not exposed) / inconclusive
	VerdictExposed                             // 200 + @odata.context + non-empty value[]
	VerdictColumnRestricted                    // 403 AttributePermissionIsMissing (table enabled, column blocked)
)

// TableVerdict inspects a table read and returns its classification plus the
// record count / total when the table is exposed.
type TableVerdict struct {
	Kind     VerdictKind
	Sample   int  // records returned in this page
	Total    *int // @odata.count when requested
	Evidence string
}

// ClassifyTableRead maps a probe result to a table exposure verdict.
func ClassifyTableRead(res saasprobe.Result) TableVerdict {
	if !res.OK {
		return TableVerdict{Kind: VerdictNone}
	}
	switch res.Status {
	case 200:
		l, ok := parseODataList(res.Body)
		if !ok || l.Context == "" || len(l.Value) == 0 {
			return TableVerdict{Kind: VerdictNone}
		}
		return TableVerdict{
			Kind:     VerdictExposed,
			Sample:   len(l.Value),
			Total:    l.Count,
			Evidence: firstRecordPreview(l.Value),
		}
	case 403:
		if isAttributePermissionError(res.Body) {
			return TableVerdict{Kind: VerdictColumnRestricted}
		}
		return TableVerdict{Kind: VerdictNone}
	default:
		// 404 (table not exposed), 401 (token needed), etc. → not a data leak.
		return TableVerdict{Kind: VerdictNone}
	}
}

// isAttributePermissionError reports whether a 403 body is the Dataverse
// "attribute is not enabled for Web Api" error (code 90040101) — meaning the
// TABLE is Web-API-enabled and anonymously reachable, but the requested column
// is not allow-listed. This still evidences an exposed table.
func isAttributePermissionError(body string) bool {
	l, ok := parseODataList(body)
	if ok && l.Error != nil {
		blob := strings.ToLower(l.Error.Code + " " + l.Error.Message + " " + l.Error.InnerError.Code + " " + l.Error.InnerError.Message)
		if strings.Contains(blob, "90040101") ||
			strings.Contains(blob, "attributepermissionismissing") ||
			strings.Contains(blob, "not enabled for web api") {
			return true
		}
	}
	lower := strings.ToLower(body)
	return strings.Contains(lower, "90040101") || strings.Contains(lower, "not enabled for web api")
}

// firstRecordPreview returns a short, redacted-length preview of the first
// returned record's field names (not values) so a finding shows what columns
// leaked without dumping PII into the report.
func firstRecordPreview(values []json.RawMessage) string {
	if len(values) == 0 {
		return ""
	}
	var rec map[string]json.RawMessage
	if err := json.Unmarshal(values[0], &rec); err != nil {
		return ""
	}
	var fields []string
	for k := range rec {
		if strings.HasPrefix(k, "@odata") {
			continue
		}
		fields = append(fields, k)
		if len(fields) >= 12 {
			break
		}
	}
	if len(fields) == 0 {
		return ""
	}
	return "columns: " + strings.Join(fields, ", ")
}
