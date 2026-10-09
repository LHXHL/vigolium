package server

import (
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

// SwaggerSchemaTypes maps every generated components.schemas entry in the
// OpenAPI spec (docs/development/api-swagger.json and its embedded copy
// swagger_spec.json) to the Go value whose JSON encoding it documents.
//
// The schema bodies are generated from these types by
// internal/tools/swaggergen (`make swagger`); descriptions, examples, enums and
// required lists are hand-written in the canonical JSON and carried across
// regenerations. TestSwaggerSchemasMatchStructs fails when a struct gains or
// loses a JSON field without the spec being regenerated, and
// TestSwaggerSchemasAreRegistered fails when the spec carries a schema that
// is neither listed here nor in SwaggerHandWrittenSchemas.
//
// A nested struct whose type is also listed here is emitted as a $ref to its
// entry; any other nested struct is inlined.
var SwaggerSchemaTypes = map[string]any{
	// Info / auth
	"AppInfoResponse":    AppInfoResponse{},
	"HealthResponse":     HealthResponse{},
	"ServerInfoResponse": ServerInfoResponse{},
	"LoginRequest":       LoginRequest{},
	"LoginResponse":      LoginResponse{},
	"LoginUser":          LoginUser{},
	"ErrorResponse":      ErrorResponse{},
	"PaginatedResponse":  PaginatedResponse{},

	// Scans
	"RunScanRequest":        RunScanRequest{},
	"ScanAllRecordsRequest": ScanAllRecordsRequest{},
	"ScanURLRequest":        ScanURLRequest{},
	"ScanRequestRequest":    ScanRequestRequest{},
	"ScanRecordsRequest":    ScanRecordsRequest{},
	"ScanResponse":          ScanResponse{},
	"ScanStatusResponse":    ScanStatusResponse{},

	// Ingest
	"IngestHTTPRequest":  IngestHTTPRequest{},
	"IngestHTTPResponse": IngestHTTPResponse{},

	// Agent
	"AgentRunRequest":           AgenticScanRequest{},
	"AgentAutopilotRequest":     AgentAutopilotRequest{},
	"AgentSwarmRequest":         AgentSwarmRequest{},
	"AgentAuditRequest":         AgentAuditRequest{},
	"AgentRunResponse":          AgenticScanResponse{},
	"AgentRunStatusResponse":    AgenticScanStatusResponse{},
	"AgentSessionSummary":       AgentSessionSummary{},
	"AgentSessionDetail":        AgentSessionDetail{},
	"AgentArtifact":             AgentArtifact{},
	"AgentArtifactListResponse": AgentArtifactListResponse{},
	"ChatCompletionRequest":     ChatCompletionRequest{},
	"ChatCompletionResponse":    ChatCompletionResponse{},

	// Data
	"Finding":         database.Finding{},
	"HTTPRecord":      swaggerHTTPRecord{},
	"EmbeddedParam":   database.EmbeddedParam{},
	"OASTInteraction": database.OASTInteraction{},
	"ModuleInfo":      ModuleInfo{},
	"StatsResponse":   StatsResponse{},

	// Scope / config / projects
	"ScopeConfig":          config.ScopeConfig{},
	"ScopeRule":            config.ScopeRule{},
	"ScopeUpdateResponse":  ScopeUpdateResponse{},
	"ConfigListResponse":   ConfigListResponse{},
	"ConfigEntryResponse":  ConfigEntryResponse{},
	"ConfigUpdateRequest":  ConfigUpdateRequest{},
	"ConfigUpdateResponse": ConfigUpdateResponse{},
	"ProjectRequest":       ProjectRequest{},
	"ProjectStats":         ProjectStats{},

	// Extensions
	"ExtensionInfo":        ExtensionInfo{},
	"ExtensionDetail":      ExtensionDetail{},
	"ExtensionEditRequest": ExtensionEditRequest{},
	"ExtensionAPIFunction": ExtensionAPIFunction{},
}

// SwaggerHandWrittenSchemas lists components.schemas entries that have no Go
// struct behind them and are maintained by hand in the canonical JSON. Keep it
// empty unless a schema genuinely cannot be derived from a type.
var SwaggerHandWrittenSchemas = map[string]bool{}

// swaggerHTTPRecord documents the wire shape of database.HTTPRecord: its
// MarshalJSON emits the stored columns plus four fields derived from the raw
// request and response. Keep the extra fields in step with
// (*database.HTTPRecord).MarshalJSON.
type swaggerHTTPRecord struct {
	*database.HTTPRecord
	RequestHeaders  map[string][]string `json:"request_headers,omitempty"`
	RequestBody     []byte              `json:"request_body,omitempty"`
	ResponseHeaders map[string][]string `json:"response_headers,omitempty"`
	ResponseBody    []byte              `json:"response_body,omitempty"`
}
