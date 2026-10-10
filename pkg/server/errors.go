package server

import (
	"errors"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
)

var (
	ErrMissingAuthHeader       = errors.New("missing Authorization header")
	ErrInvalidAuthToken        = errors.New("invalid Bearer token")
	ErrMissingMode             = errors.New("'input_mode' field is required")
	ErrInvalidMode             = errors.New("unsupported input mode")
	ErrMissingContent          = errors.New("'content', 'content_base64', or 'http_request_base64' is required")
	ErrQueueFull               = errors.New("queue is full, try again later")
	ErrServerClosed            = errors.New("server is shutting down")
	ErrDatabaseRequired        = errors.New("database is required for this endpoint")
	ErrScanAlreadyRunning      = errors.New("a scan is already running")
	ErrNoRecordsToScan         = errors.New("no records found after scan cursor")
	ErrAgentNotFound           = errors.New("agent run not found")
	ErrMissingPrompt           = errors.New("prompt_template, prompt_file, or prompt is required")
	ErrMissingTarget           = errors.New("'target' field is required")
	ErrRecordNotFound          = errors.New("HTTP record not found")
	ErrFindingNotFound         = errors.New("finding not found")
	ErrOASTInteractionNotFound = errors.New("OAST interaction not found")
	ErrMissingURL              = errors.New("'url' field is required")
	ErrMissingRawRequest       = errors.New("'raw_request' field is required")
	ErrInvalidRawRequest       = errors.New("failed to parse raw HTTP request")
	ErrScanNotFound            = errors.New("scan not found")
	ErrMissingRecordUUIDs      = errors.New("'record_uuids' field is required")
	ErrNoValidRecords          = errors.New("no valid records found for the provided UUIDs")
	ErrExtensionNotFound       = errors.New("extension not found")
	ErrForbidden               = errors.New("insufficient permissions")
	ErrInvalidCredentials      = errors.New("invalid username or access code")
	ErrProjectNotFound         = errors.New("project not found")
	ErrInvalidProjectUUID      = errors.New("X-Project-UUID is not a valid UUID")
)

// errorCodeSentinels maps the sentinels above (and the database package's) to
// the string code a REST error carries. errorCodeFor walks it in order with
// errors.Is, so a wrapped sentinel ("failed to load scan: %w") still
// classifies; anything unlisted falls back to the HTTP status's code.
var errorCodeSentinels = []struct {
	err  error
	code apicontract.ErrorCode
}{
	{database.ErrDatabaseLocked, apicontract.CodeDatabaseLocked},
	{database.ErrSchemaTooNew, apicontract.CodeSchemaTooNew},
	{database.ErrSchemaOutdated, apicontract.CodeSchemaOutdated},
	{ErrDatabaseRequired, apicontract.CodeDatabaseUnavailable},
	{ErrProjectNotFound, apicontract.CodeProjectNotFound},
	{ErrInvalidProjectUUID, apicontract.CodeInvalidProjectUUID},
	{ErrMissingAuthHeader, apicontract.CodeUnauthorized},
	{ErrInvalidAuthToken, apicontract.CodeUnauthorized},
	{ErrInvalidCredentials, apicontract.CodeUnauthorized},
	{ErrForbidden, apicontract.CodeForbidden},
	{ErrQueueFull, apicontract.CodeQueueFull},
	{ErrServerClosed, apicontract.CodeServiceUnavailable},
	{ErrScanAlreadyRunning, apicontract.CodeConflict},
	{ErrScanNotFound, apicontract.CodeScanNotFound},
	{database.ErrScanNotFound, apicontract.CodeScanNotFound},
	{ErrRecordNotFound, apicontract.CodeRecordNotFound},
	{ErrNoValidRecords, apicontract.CodeRecordNotFound},
	{ErrFindingNotFound, apicontract.CodeFindingNotFound},
	{ErrAgentNotFound, apicontract.CodeNotFound},
	{ErrOASTInteractionNotFound, apicontract.CodeNotFound},
	{ErrExtensionNotFound, apicontract.CodeNotFound},
	{database.ErrTableNotFound, apicontract.CodeNotFound},
	{ErrInvalidMode, apicontract.CodeUnsupportedInputMode},
	{ErrInvalidRawRequest, apicontract.CodeInputUnparsed},
	{ErrMissingMode, apicontract.CodeInvalidRequest},
	{ErrMissingContent, apicontract.CodeInvalidRequest},
	{ErrMissingPrompt, apicontract.CodeInvalidRequest},
	{ErrMissingTarget, apicontract.CodeInvalidRequest},
	{ErrMissingURL, apicontract.CodeInvalidRequest},
	{ErrMissingRawRequest, apicontract.CodeInvalidRequest},
	{ErrMissingRecordUUIDs, apicontract.CodeInvalidRequest},
}
