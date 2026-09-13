package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats/curl"
	"github.com/vigolium/vigolium/pkg/input/formats/har"
	"github.com/vigolium/vigolium/pkg/input/formats/openapi"
	"github.com/vigolium/vigolium/pkg/input/formats/postman"
	"github.com/vigolium/vigolium/pkg/storagesig"
	"go.uber.org/zap"
)

// buildScopeMatchInput extracts scope-relevant fields from an HttpRequestResponse.
func buildScopeMatchInput(rr *httpmsg.HttpRequestResponse) config.ScopeMatchInput {
	input := config.ScopeMatchInput{
		Host:               rr.Service().Host(),
		Path:               rr.Request().Path(),
		RequestContentType: rr.Request().Header("Content-Type"),
		RequestRaw:         string(rr.Request().Raw()),
	}
	if rr.HasResponse() {
		resp := rr.Response()
		input.StatusCode = resp.StatusCode()
		input.ResponseContentType = resp.Header("Content-Type")
		input.ResponseBody = resp.BodyToString()
	}
	return input
}

// isIngestInScope checks whether a request/response pair should be saved.
// Static file filtering is always enforced (regardless of applied_on_ingest).
// Full scope rules are only enforced when applied_on_ingest is true.
func (h *Handlers) isIngestInScope(rr *httpmsg.HttpRequestResponse) bool {
	if h.settings == nil {
		return true
	}
	matcher := h.getScopeMatcher()
	if matcher == nil {
		return true
	}
	// Always filter static files regardless of applied_on_ingest — except
	// object-storage assets, kept as metadata-only (body stripped) so the CDN
	// traversal modules can probe storage-fronted static URLs.
	if matcher.IsStaticFile(rr.Request().Path()) {
		var hg storagesig.HeaderGetter
		if rr.HasResponse() && rr.Response() != nil {
			hg = rr.Response()
		}
		if !storagesig.KeepStaticAsMeta(rr.Request().Path(), hg) {
			return false
		}
		if rr.Response() != nil {
			rr.Response().TruncateBody(0)
		}
	}
	if !h.settings.Scope.AppliedOnIngest {
		return true
	}
	return matcher.InScope(buildScopeMatchInput(rr))
}

// fetchResponseIfNeeded fetches the HTTP response for a request if one isn't
// already attached and fetching is not disabled. On failure it returns the
// original request-only record so ingestion can proceed.
func (h *Handlers) fetchResponseIfNeeded(rr *httpmsg.HttpRequestResponse) *httpmsg.HttpRequestResponse {
	if rr.HasResponse() {
		return rr
	}
	if h.config.DisableFetchResponse || h.httpRequester == nil {
		return rr
	}

	respChain, elapsed, err := h.httpRequester.Execute(rr, http.Options{})
	if err != nil {
		zap.L().Debug("Failed to fetch response during ingestion",
			zap.String("url", rr.Target()), zap.Error(err))
		return rr
	}

	fullResp := respChain.FullResponseBytes()
	raw := make([]byte, len(fullResp))
	copy(raw, fullResp)
	respChain.Close()

	// This record is persisted, and this send is the only chance to record its
	// timing — the converter cannot recover it from the bytes.
	return rr.WithResponse(httpmsg.NewHttpResponseWithDuration(raw, elapsed))
}

// IngestSourceHeader lets a client declare which tool the traffic it is pushing
// came from, so a record ingested by the Caido plugin is distinguishable from
// one pushed by curl. Mirrors the X-Project-UUID convention: a header rather
// than a body field, because the seven ingest modes share three save helpers
// but seven request shapes.
const IngestSourceHeader = "X-Vigolium-Source"

// ingestSource resolves the source label for an ingestion request: the client's
// declared tool when it names an allowed one, otherwise the generic
// ingest-server label this endpoint has always written.
//
// The allowlist is database.IsBridgeRecordSource rather than a local table, and
// it is an allowlist and not a passthrough on purpose: http_records.source is
// not only a display label, it decides which rows scan-on-receive feeds back
// into a running scan (database.IngestRecordSources) and which rows the executor
// treats as its own artefacts. A client free to send source="scanner" could
// silently exclude its own traffic from the scan it just asked for.
func ingestSource(c fiber.Ctx) string {
	declared := strings.ToLower(strings.TrimSpace(c.Get(IngestSourceHeader)))
	if declared == "" {
		return database.RecordSourceIngestServer
	}
	if database.IsBridgeRecordSource(declared) {
		return declared
	}
	zap.L().Debug("ignoring unrecognised ingest source header",
		zap.String("header", IngestSourceHeader), zap.String("declared", declared))
	return database.RecordSourceIngestServer
}

// saveRecord persists an HTTP record, routing through the RecordWriter when
// available (batched writes) or falling back to a direct repository insert.
func (h *Handlers) saveRecord(ctx context.Context, rr *httpmsg.HttpRequestResponse, source string, projectUUID string) (string, error) {
	if h.recordWriter != nil {
		return h.recordWriter.Write(ctx, rr, source, projectUUID)
	}
	return h.repo.SaveRecord(ctx, rr, source, projectUUID)
}

// ingestBatchChunk bounds how many records a bulk importer accumulates before a
// batched flush, so memory stays bounded while a single producer still fills real
// writer batches instead of paying one flush interval per record.
const ingestBatchChunk = 256

// saveRecordBatch persists a slice of records in one batched operation. Unlike a
// Write-in-a-loop (each Write blocks until its own record is flushed, so a lone
// bulk importer never fills a batch), the RecordWriter's SaveRecordBatch enqueues
// everything before awaiting, so the records coalesce into real transactions.
// Returns the number persisted (new + deduplicated) and any errors encountered.
func (h *Handlers) saveRecordBatch(ctx context.Context, records []*httpmsg.HttpRequestResponse, source, projectUUID string) (int, []string) {
	if len(records) == 0 {
		return 0, nil
	}
	var uuids []string
	var err error
	if h.recordWriter != nil {
		uuids, err = h.recordWriter.SaveRecordBatch(ctx, records, source, projectUUID)
	} else {
		uuids, err = h.repo.SaveRecordBatch(ctx, records, source, projectUUID)
	}
	saved := database.CountSaved(uuids)
	var errs []string
	if err != nil {
		errs = append(errs, err.Error())
	}
	return saved, errs
}

// ingestAccumulator batches in-scope records from a bulk importer's parser
// callback, flushing in bounded chunks so memory stays bounded while records
// still coalesce into real writer batches (instead of one blocking flush per
// record). Not safe for concurrent use — parser callbacks run sequentially.
type ingestAccumulator struct {
	h           *Handlers
	ctx         context.Context
	source      string
	projectUUID string
	batch       []*httpmsg.HttpRequestResponse
	imported    int
	errors      []string
}

func (h *Handlers) newIngestAccumulator(ctx context.Context, source, projectUUID string) *ingestAccumulator {
	return &ingestAccumulator{
		h:           h,
		ctx:         ctx,
		source:      source,
		projectUUID: projectUUID,
		batch:       make([]*httpmsg.HttpRequestResponse, 0, ingestBatchChunk),
	}
}

// add queues a record, flushing automatically when a chunk fills.
func (a *ingestAccumulator) add(rr *httpmsg.HttpRequestResponse) {
	a.batch = append(a.batch, rr)
	if len(a.batch) >= ingestBatchChunk {
		a.flush()
	}
}

// flush persists the currently-queued records.
func (a *ingestAccumulator) flush() {
	if len(a.batch) == 0 {
		return
	}
	n, errs := a.h.saveRecordBatch(a.ctx, a.batch, a.source, a.projectUUID)
	a.imported += n
	a.errors = append(a.errors, errs...)
	a.batch = a.batch[:0]
}

// finish drains the final partial chunk and returns the totals. Callers use this
// once parsing completes instead of calling flush + reading the fields directly.
func (a *ingestAccumulator) finish() (imported int, errs []string) {
	a.flush()
	return a.imported, a.errors
}

// HandleIngestHTTP handles POST /api/ingest-http
func (h *Handlers) HandleIngestHTTP(c fiber.Ctx) error {
	if h.repo == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	var req IngestHTTPRequest
	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid JSON: " + err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	if req.InputMode == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: ErrMissingMode.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	// Detached on purpose: ingestion persists records, and when the async
	// RecordWriter is enabled it enqueues the write then flushes on a background
	// context — the record lands regardless of the client. Binding the request
	// context here would let a client disconnect (between enqueue and flush)
	// return an error for a record that was in fact saved. Persistence must be
	// durable, so we use a background context.
	ctx := context.Background()

	switch req.InputMode {
	case "burp_base64":
		return h.ingestBurpBase64(c, ctx, &req)
	case "curl":
		return h.ingestCurl(c, ctx, &req)
	case "openapi", "swagger":
		return h.ingestOpenAPI(c, ctx, &req)
	case "postman_collection":
		return h.ingestPostman(c, ctx, &req)
	case "har", "http_archive":
		return h.ingestHAR(c, ctx, &req)
	case "url":
		return h.ingestURL(c, ctx, &req)
	case "url_file":
		return h.ingestURLFile(c, ctx, &req)
	default:
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: ErrInvalidMode.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}
}

// resolveContent returns content from the request, decoding base64 if needed.
func resolveContent(req *IngestHTTPRequest) (string, error) {
	if req.Content != "" {
		return req.Content, nil
	}
	if req.ContentBase64 != "" {
		data, err := base64.StdEncoding.DecodeString(req.ContentBase64)
		if err != nil {
			return "", fmt.Errorf("invalid base64 in content_base64: %w", err)
		}
		return string(data), nil
	}
	return "", ErrMissingContent
}

func (h *Handlers) ingestBurpBase64(c fiber.Ctx, ctx context.Context, req *IngestHTTPRequest) error {
	if req.HTTPRequestBase64 == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "'http_request_base64' is required for burp_base64 mode",
			Code:  fiber.StatusBadRequest,
		})
	}

	rawReq, err := base64.StdEncoding.DecodeString(req.HTTPRequestBase64)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid base64 in http_request_base64: " + err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	var rr *httpmsg.HttpRequestResponse
	if req.URL != "" {
		rr, err = httpmsg.ParseRawRequestWithURL(string(rawReq), req.URL)
	} else {
		rr, err = httpmsg.ParseRawRequest(string(rawReq))
	}
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "failed to parse raw request: " + err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	// Attach response if provided
	if req.HTTPResponseBase64 != "" {
		rawResp, err := base64.StdEncoding.DecodeString(req.HTTPResponseBase64)
		if err == nil {
			resp := httpmsg.NewHttpResponse(rawResp)
			if resp != nil {
				rr = rr.WithResponse(resp)
			}
		}
	}

	rr = h.fetchResponseIfNeeded(rr)

	if !h.isIngestInScope(rr) {
		return c.JSON(IngestHTTPResponse{
			ProjectUUID: getProjectUUID(c),
			Imported:    0,
			Skipped:     1,
			Message:     "filtered by scope",
		})
	}

	if _, err := h.saveRecord(ctx, rr, ingestSource(c), getProjectUUID(c)); err != nil {
		zap.L().Error("Failed to save ingested record", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to save record: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	return c.JSON(IngestHTTPResponse{
		ProjectUUID: getProjectUUID(c),
		Imported:    1,
		Message:     "imported 1 request",
	})
}

func (h *Handlers) ingestCurl(c fiber.Ctx, ctx context.Context, req *IngestHTTPRequest) error {
	content, err := resolveContent(req)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	rr, err := curl.ParseSingleCommand(content)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "failed to parse curl command: " + err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	if req.URL != "" {
		if svc, svcErr := httpmsg.ParseService(req.URL); svcErr == nil {
			rr = rr.WithService(svc)
		}
	}

	rr = h.fetchResponseIfNeeded(rr)

	if !h.isIngestInScope(rr) {
		return c.JSON(IngestHTTPResponse{
			ProjectUUID: getProjectUUID(c),
			Imported:    0,
			Skipped:     1,
			Message:     "filtered by scope",
		})
	}

	if _, err := h.saveRecord(ctx, rr, ingestSource(c), getProjectUUID(c)); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to save record: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	return c.JSON(IngestHTTPResponse{
		ProjectUUID: getProjectUUID(c),
		Imported:    1,
		Message:     "imported 1 request from curl",
	})
}

func (h *Handlers) ingestOpenAPI(c fiber.Ctx, ctx context.Context, req *IngestHTTPRequest) error {
	content, err := resolveContent(req)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	data := []byte(content)
	ext := openapi.DetectFormatFromContent(data)

	var skipped int
	acc := h.newIngestAccumulator(ctx, ingestSource(c), getProjectUUID(c))

	var urlOverrideSvc *httpmsg.Service
	if req.URL != "" {
		if svc, svcErr := httpmsg.ParseService(req.URL); svcErr == nil {
			urlOverrideSvc = svc
		}
	}

	opts := openapi.Options{}
	if req.URL == "" {
		opts.UseSpecServers = true
	}
	parseErr := openapi.ParseSwagger(data, ext, opts, func(rr *httpmsg.HttpRequestResponse) bool {
		if urlOverrideSvc != nil {
			rr = rr.WithService(urlOverrideSvc)
		}
		rr = h.fetchResponseIfNeeded(rr)
		if !h.isIngestInScope(rr) {
			skipped++
			return true
		}
		acc.add(rr)
		return true
	})

	if parseErr != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "failed to parse OpenAPI spec: " + parseErr.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}
	imported, errors := acc.finish()

	msg := fmt.Sprintf("imported %d requests from OpenAPI spec", imported)
	if skipped > 0 {
		msg += fmt.Sprintf(" (%d filtered by scope)", skipped)
	}

	return c.JSON(IngestHTTPResponse{
		ProjectUUID: getProjectUUID(c),
		Imported:    imported,
		Skipped:     skipped,
		Errors:      errors,
		Message:     msg,
	})
}

func (h *Handlers) ingestPostman(c fiber.Ctx, ctx context.Context, req *IngestHTTPRequest) error {
	content, err := resolveContent(req)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	parser := postman.New()
	var skipped int
	acc := h.newIngestAccumulator(ctx, ingestSource(c), getProjectUUID(c))

	var urlOverrideSvc *httpmsg.Service
	if req.URL != "" {
		if svc, svcErr := httpmsg.ParseService(req.URL); svcErr == nil {
			urlOverrideSvc = svc
		}
	}

	parseErr := parser.ParseFromData([]byte(content), func(rr *httpmsg.HttpRequestResponse) bool {
		if urlOverrideSvc != nil {
			rr = rr.WithService(urlOverrideSvc)
		}
		rr = h.fetchResponseIfNeeded(rr)
		if !h.isIngestInScope(rr) {
			skipped++
			return true
		}
		acc.add(rr)
		return true
	})

	if parseErr != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "failed to parse Postman collection: " + parseErr.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}
	imported, errors := acc.finish()

	msg := fmt.Sprintf("imported %d requests from Postman collection", imported)
	if skipped > 0 {
		msg += fmt.Sprintf(" (%d filtered by scope)", skipped)
	}

	return c.JSON(IngestHTTPResponse{
		ProjectUUID: getProjectUUID(c),
		Imported:    imported,
		Skipped:     skipped,
		Errors:      errors,
		Message:     msg,
	})
}

func (h *Handlers) ingestURL(c fiber.Ctx, ctx context.Context, req *IngestHTTPRequest) error {
	content, err := resolveContent(req)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	rr, err := httpmsg.GetRawRequestFromURL(strings.TrimSpace(content))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "failed to create request from URL: " + err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	if req.URL != "" {
		if svc, svcErr := httpmsg.ParseService(req.URL); svcErr == nil {
			rr = rr.WithService(svc)
		}
	}

	rr = h.fetchResponseIfNeeded(rr)

	if !h.isIngestInScope(rr) {
		return c.JSON(IngestHTTPResponse{
			ProjectUUID: getProjectUUID(c),
			Imported:    0,
			Skipped:     1,
			Message:     "filtered by scope",
		})
	}

	if _, err := h.saveRecord(ctx, rr, ingestSource(c), getProjectUUID(c)); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to save record: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	return c.JSON(IngestHTTPResponse{
		ProjectUUID: getProjectUUID(c),
		Imported:    1,
		Message:     "imported 1 request from URL",
	})
}

func (h *Handlers) ingestHAR(c fiber.Ctx, ctx context.Context, req *IngestHTTPRequest) error {
	content, err := resolveContent(req)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	parser := har.New()
	var skipped int
	acc := h.newIngestAccumulator(ctx, ingestSource(c), getProjectUUID(c))

	var urlOverrideSvc *httpmsg.Service
	if req.URL != "" {
		if svc, svcErr := httpmsg.ParseService(req.URL); svcErr == nil {
			urlOverrideSvc = svc
		}
	}

	// Accumulate in-scope records and persist them in bounded batches, so a large
	// HAR imports in a handful of transactions instead of one blocking flush per
	// record.
	parseErr := parser.ParseFromData([]byte(content), func(rr *httpmsg.HttpRequestResponse) bool {
		if urlOverrideSvc != nil {
			rr = rr.WithService(urlOverrideSvc)
		}
		rr = h.fetchResponseIfNeeded(rr)
		if !h.isIngestInScope(rr) {
			skipped++
			return true
		}
		acc.add(rr)
		return true
	})

	if parseErr != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "failed to parse HAR file: " + parseErr.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}
	imported, errors := acc.finish()

	msg := fmt.Sprintf("imported %d requests from HAR file", imported)
	if skipped > 0 {
		msg += fmt.Sprintf(" (%d filtered by scope)", skipped)
	}

	return c.JSON(IngestHTTPResponse{
		ProjectUUID: getProjectUUID(c),
		Imported:    imported,
		Skipped:     skipped,
		Errors:      errors,
		Message:     msg,
	})
}

func (h *Handlers) ingestURLFile(c fiber.Ctx, ctx context.Context, req *IngestHTTPRequest) error {
	content, err := resolveContent(req)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	var skipped int
	var parseErrors []string // per-line parse errors keep their line context
	acc := h.newIngestAccumulator(ctx, ingestSource(c), getProjectUUID(c))

	var urlOverrideSvc *httpmsg.Service
	if req.URL != "" {
		if svc, svcErr := httpmsg.ParseService(req.URL); svcErr == nil {
			urlOverrideSvc = svc
		}
	}

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		rr, err := httpmsg.GetRawRequestFromURL(line)
		if err != nil {
			parseErrors = append(parseErrors, fmt.Sprintf("%s: %s", line, err.Error()))
			continue
		}

		if urlOverrideSvc != nil {
			rr = rr.WithService(urlOverrideSvc)
		}

		rr = h.fetchResponseIfNeeded(rr)

		if !h.isIngestInScope(rr) {
			skipped++
			continue
		}

		acc.add(rr)
	}
	imported, accErrs := acc.finish()
	errors := append(parseErrors, accErrs...)

	msg := fmt.Sprintf("imported %d requests from URL list", imported)
	if skipped > 0 {
		msg += fmt.Sprintf(" (%d filtered by scope)", skipped)
	}

	return c.JSON(IngestHTTPResponse{
		ProjectUUID: getProjectUUID(c),
		Imported:    imported,
		Skipped:     skipped,
		Errors:      errors,
		Message:     msg,
	})
}
