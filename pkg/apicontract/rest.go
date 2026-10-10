package apicontract

import (
	"bytes"
	"encoding/json"
	"sort"
)

// REST API versions. The REST surface is versioned by negotiation rather than
// by URL prefix: a client asks for v2 with any of
//
//	Accept: application/vnd.vigolium.v2+json
//	Vigolium-Api-Version: 2
//	?api_version=2
//
// and the server answers every response with the version it rendered in the
// Vigolium-Api-Version header. A request that names none gets the server's
// default (server.api_version_default, 1 in this release).
//
// v1 is the historical shape, extended only additively: an error body is
// {error, code (the HTTP status), error_code, details} and a paginated list is
// {data, total, limit, offset, has_more, project_uuid, schema_version, command}.
//
// v2 speaks the same envelope as the CLI's -j documents: a list is RESTList
// (items, never data) and an error is RESTErrorEnvelope (error is an object
// carrying the string code). Server-sent event streams are never wrapped.
const (
	RESTAPIVersion1 = 1
	RESTAPIVersion2 = 2

	// RESTAPIVersionHeader is both the request header that selects a version
	// and the response header that reports the one rendered.
	RESTAPIVersionHeader = "Vigolium-Api-Version"
	// RESTAPIVersionQuery is the query-parameter form of the selector.
	RESTAPIVersionQuery = "api_version"
	// RESTMediaTypeV1 / RESTMediaTypeV2 are the Accept media types that select a
	// version.
	RESTMediaTypeV1 = "application/vnd.vigolium.v1+json"
	RESTMediaTypeV2 = "application/vnd.vigolium.v2+json"

	// ProjectCreateHeader opts a request into creating the project named by
	// X-Project-UUID when it does not exist yet ("1" or "true"). The query
	// form is ?create=1.
	ProjectCreateHeader = "X-Project-Create"
)

// RESTList is the v2 list envelope. SchemaVersion is the REST API version (2).
// Extra holds endpoint-specific fields (a table's column list, whether
// extensions are enabled, …) and is marshaled into the same object, the way the
// CLI envelope carries its command-specific fields.
type RESTList struct {
	SchemaVersion int    `json:"schema_version"`
	Command       string `json:"command"`
	Kind          string `json:"kind"`
	OK            bool   `json:"ok"`
	// Route is the matched route, "GET /api/findings".
	Route         string `json:"route"`
	ProjectUUID   string `json:"project_uuid,omitempty"`
	ProjectScoped bool   `json:"project_scoped"`
	Total         int64  `json:"total"`
	Offset        int    `json:"offset"`
	Limit         int    `json:"limit"`
	HasMore       bool   `json:"has_more"`
	// Items is always a JSON array, never null.
	Items         any    `json:"items"`
	GeneratedAt   string `json:"generated_at"`
	GeneratedAtMS int64  `json:"generated_at_ms"`

	Extra map[string]any `json:"-"`
}

// MarshalJSON renders the fixed fields followed by Extra. A key in Extra that
// collides with a fixed field is dropped: the spine is the contract.
func (l RESTList) MarshalJSON() ([]byte, error) {
	type spine RESTList
	base, err := json.Marshal(spine(l))
	if err != nil {
		return nil, err
	}
	if len(l.Extra) == 0 {
		return base, nil
	}
	extra, err := json.Marshal(l.Extra)
	if err != nil {
		return nil, err
	}
	var fixed map[string]json.RawMessage
	if err := json.Unmarshal(base, &fixed); err != nil {
		return nil, err
	}
	var add map[string]json.RawMessage
	if err := json.Unmarshal(extra, &add); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.Write(base[:len(base)-1])
	keys := make([]string, 0, len(add))
	for k := range add {
		if _, clash := fixed[k]; clash {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		buf.WriteByte(',')
		kb, _ := json.Marshal(k)
		buf.Write(kb)
		buf.WriteByte(':')
		buf.Write(add[k])
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// RESTError is the error object of a v2 error document.
type RESTError struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
	// Status is the HTTP status the response carried.
	Status  int    `json:"status"`
	Details string `json:"details,omitempty"`
}

// RESTErrorEnvelope is the v2 error document: the CLI error envelope with an
// HTTP status where the CLI has an exit code.
type RESTErrorEnvelope struct {
	SchemaVersion int       `json:"schema_version"`
	Command       string    `json:"command"`
	Route         string    `json:"route,omitempty"`
	OK            bool      `json:"ok"`
	Error         RESTError `json:"error"`
	GeneratedAt   string    `json:"generated_at"`
	GeneratedAtMS int64     `json:"generated_at_ms"`
}
