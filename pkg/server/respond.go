package server

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/scanevents"
)

// This file is the one place a REST response body's shape is decided. Every
// error goes through respondError/respondErrorMsg/respondErrorCode and every
// list through respondList/respondBespokeList, so the version a client
// negotiated (apiVersionMiddleware) is honoured everywhere and an error always
// carries its string code. TestNoInlineErrorResponse keeps it that way.

const apiVersionLocalsKey = "vigolium_api_version"

// fallbackAPIVersion is what a request is rendered in when it reaches a helper
// without having passed apiVersionMiddleware (handler unit tests mount
// handlers on a bare fiber.App). It matches the shipped default.
const fallbackAPIVersion = apicontract.RESTAPIVersion1

// normalizeAPIVersionDefault maps a configured server.api_version_default to
// a version this server speaks: 2 selects v2, anything else (0 = unset) is v1.
func normalizeAPIVersionDefault(v int) int {
	if v == apicontract.RESTAPIVersion2 {
		return apicontract.RESTAPIVersion2
	}
	return apicontract.RESTAPIVersion1
}

// parseAPIVersion reads "1", "2", "v1" or "v2".
func parseAPIVersion(s string) (int, error) {
	t := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "v")
	switch t {
	case "1":
		return apicontract.RESTAPIVersion1, nil
	case "2":
		return apicontract.RESTAPIVersion2, nil
	}
	return 0, fmt.Errorf("unsupported API version %q (supported: 1, 2)", s)
}

// negotiateAPIVersion picks the version a request asked for. Precedence: the
// ?api_version= query parameter, then the Vigolium-Api-Version header, then an
// Accept media type, then def. An explicit but unknown version is an error,
// never a silent fall back to the default.
func negotiateAPIVersion(c fiber.Ctx, def int) (int, error) {
	if q := c.Query(apicontract.RESTAPIVersionQuery); q != "" {
		return parseAPIVersion(q)
	}
	if h := c.Get(apicontract.RESTAPIVersionHeader); h != "" {
		return parseAPIVersion(h)
	}
	accept := strings.ToLower(c.Get(fiber.HeaderAccept))
	switch {
	case strings.Contains(accept, apicontract.RESTMediaTypeV2):
		return apicontract.RESTAPIVersion2, nil
	case strings.Contains(accept, apicontract.RESTMediaTypeV1):
		return apicontract.RESTAPIVersion1, nil
	}
	return def, nil
}

// apiVersionMiddleware negotiates the response version for every request,
// stores it for the response helpers, and reports it in the
// Vigolium-Api-Version response header. defaultVersion is
// server.api_version_default.
func apiVersionMiddleware(defaultVersion int) fiber.Handler {
	def := normalizeAPIVersionDefault(defaultVersion)
	return func(c fiber.Ctx) error {
		v, err := negotiateAPIVersion(c, def)
		if err != nil {
			v = def
		}
		c.Locals(apiVersionLocalsKey, v)
		c.Set(apicontract.RESTAPIVersionHeader, strconv.Itoa(v))
		c.Vary(fiber.HeaderAccept, apicontract.RESTAPIVersionHeader)
		if err != nil {
			return respondErrorCode(c, fiber.StatusBadRequest, apicontract.CodeUnsupportedAPIVersion, err.Error())
		}
		return c.Next()
	}
}

// requestAPIVersion is the version this response is rendered in.
func requestAPIVersion(c fiber.Ctx) int {
	if v, ok := c.Locals(apiVersionLocalsKey).(int); ok {
		return v
	}
	v, err := negotiateAPIVersion(c, fallbackAPIVersion)
	if err != nil {
		v = fallbackAPIVersion
	}
	c.Set(apicontract.RESTAPIVersionHeader, strconv.Itoa(v))
	return v
}

// --- errors -----------------------------------------------------------------

// statusErrorCode is the code an error gets when nothing more specific is
// known: the HTTP status's class.
func statusErrorCode(status int) apicontract.ErrorCode {
	switch status {
	case fiber.StatusBadRequest, fiber.StatusUnprocessableEntity:
		return apicontract.CodeInvalidRequest
	case fiber.StatusUnauthorized:
		return apicontract.CodeUnauthorized
	case fiber.StatusForbidden:
		return apicontract.CodeForbidden
	case fiber.StatusNotFound, fiber.StatusGone:
		return apicontract.CodeNotFound
	case fiber.StatusMethodNotAllowed:
		return apicontract.CodeMethodNotAllowed
	case fiber.StatusConflict:
		return apicontract.CodeConflict
	case fiber.StatusRequestEntityTooLarge:
		return apicontract.CodePayloadTooLarge
	case fiber.StatusTooManyRequests:
		return apicontract.CodeRateLimited
	case fiber.StatusServiceUnavailable:
		return apicontract.CodeServiceUnavailable
	}
	if status >= 500 {
		return apicontract.CodeInternalError
	}
	return apicontract.CodeInvalidRequest
}

// errorCodeFor classifies err: a known sentinel anywhere in its chain wins
// (errorCodeSentinels, errors.go), otherwise the status decides.
func errorCodeFor(err error, status int) apicontract.ErrorCode {
	if err != nil {
		for _, s := range errorCodeSentinels {
			if errors.Is(err, s.err) {
				return s.code
			}
		}
	}
	return statusErrorCode(status)
}

// respondError writes err as the response, classified by errorCodeFor.
// details are joined with "; ".
func respondError(c fiber.Ctx, status int, err error, details ...string) error {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	return writeError(c, status, errorCodeFor(err, status), msg, details)
}

// respondErrorMsg writes a plain message, classified by status alone.
func respondErrorMsg(c fiber.Ctx, status int, msg string, details ...string) error {
	return writeError(c, status, statusErrorCode(status), msg, details)
}

// respondErrorCode writes msg with an explicit code.
func respondErrorCode(c fiber.Ctx, status int, code apicontract.ErrorCode, msg string, details ...string) error {
	if code == "" {
		code = statusErrorCode(status)
	}
	return writeError(c, status, code, msg, details)
}

func writeError(c fiber.Ctx, status int, code apicontract.ErrorCode, msg string, details []string) error {
	if msg == "" {
		msg = statusMessage(status)
	}
	detail := strings.Join(nonEmpty(details), "; ")
	if requestAPIVersion(c) == apicontract.RESTAPIVersion2 {
		now := time.Now()
		return c.Status(status).JSON(apicontract.RESTErrorEnvelope{
			SchemaVersion: apicontract.RESTAPIVersion2,
			Command:       routeCommand(c),
			Route:         routeKey(c),
			OK:            false,
			Error: apicontract.RESTError{
				Code:    code,
				Message: msg,
				Status:  status,
				Details: detail,
			},
			GeneratedAt:   scanevents.FormatTime(now),
			GeneratedAtMS: scanevents.EpochMillis(now),
		})
	}
	return c.Status(status).JSON(ErrorResponse{
		Error:     msg,
		Code:      status,
		ErrorCode: string(code),
		Details:   detail,
	})
}

func statusMessage(status int) string {
	return strings.TrimSpace(fiber.NewError(status).Message)
}

func nonEmpty(in []string) []string {
	out := in[:0:0]
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// apiErrorHandler renders errors a handler returned (or the router raised:
// unknown route, wrong method, a recovered panic) through the same error
// shape as everything else. Fiber's default would answer text/plain.
func apiErrorHandler(c fiber.Ctx, err error) error {
	status := fiber.StatusInternalServerError
	msg := ""
	var fe *fiber.Error
	if errors.As(err, &fe) {
		status = fe.Code
		msg = fe.Message
	} else if err != nil {
		msg = err.Error()
	}
	return respondError(c, status, errors.New(msg))
}

// --- lists ------------------------------------------------------------------

// respondList writes a paginated list. v1 is page itself (the historical
// PaginatedResponse) stamped with schema_version and command; v2 is the list
// envelope with the rows under items.
func respondList(c fiber.Ctx, page PaginatedResponse) error {
	if requestAPIVersion(c) == apicontract.RESTAPIVersion2 {
		return c.JSON(listEnvelope(c, page, nil, nil))
	}
	page.SchemaVersion = apicontract.RESTAPIVersion1
	page.Command = routeCommand(c)
	page.Data = nonNilItems(page.Data)
	return c.JSON(page)
}

// respondBespokeList writes a list endpoint whose v1 body predates the
// paginated shape ({modules,total}, a bare array, …). v1 sends v1Body
// untouched; v2 wraps page.Data in the list envelope with extra flattened in.
// page.HasMore is derived when the handler did not set it.
func respondBespokeList(c fiber.Ctx, v1Body any, page PaginatedResponse, extra map[string]any) error {
	if requestAPIVersion(c) != apicontract.RESTAPIVersion2 {
		return c.JSON(v1Body)
	}
	return c.JSON(listEnvelope(c, page, extra, nil))
}

// respondMutationList writes a mutation that answers with the rows it acted
// on (POST /api/findings/:id/verify): v1 sends v1Body untouched; v2 is the list
// envelope with kind "mutation", the CLI mutation document's kind, and extra
// (changed, action, …) flattened in. A page carrying ProjectUUID is reported
// project-scoped.
func respondMutationList(c fiber.Ctx, v1Body any, page PaginatedResponse, extra map[string]any) error {
	if requestAPIVersion(c) != apicontract.RESTAPIVersion2 {
		return c.JSON(v1Body)
	}
	scoped := page.ProjectUUID != ""
	env := listEnvelope(c, page, extra, &scoped)
	env.Kind = "mutation"
	return c.JSON(env)
}

// respondBespokeListScoped is respondBespokeList for a route whose project
// scoping depends on the request (the generic table API).
func respondBespokeListScoped(c fiber.Ctx, v1Body any, page PaginatedResponse, extra map[string]any, projectScoped bool) error {
	if requestAPIVersion(c) != apicontract.RESTAPIVersion2 {
		return c.JSON(v1Body)
	}
	return c.JSON(listEnvelope(c, page, extra, &projectScoped))
}

func listEnvelope(c fiber.Ctx, page PaginatedResponse, extra map[string]any, scopedOverride *bool) apicontract.RESTList {
	items := nonNilItems(page.Data)
	n := itemCount(items)
	limit := page.Limit
	if limit == 0 && page.Offset == 0 {
		// An unpaginated endpoint returned everything it had.
		limit = n
	}
	hasMore := page.HasMore
	if !hasMore && page.Total > 0 {
		hasMore = int64(page.Offset+n) < page.Total
	}
	contract := routeContractFor(c)
	scoped := contract.ProjectScoped
	if scopedOverride != nil {
		scoped = *scopedOverride
	}
	projectUUID := page.ProjectUUID
	if projectUUID == "" && scoped {
		projectUUID = getProjectUUID(c)
	}
	now := time.Now()
	return apicontract.RESTList{
		SchemaVersion: apicontract.RESTAPIVersion2,
		Command:       routeCommand(c),
		Kind:          "read",
		OK:            true,
		Route:         routeKey(c),
		ProjectUUID:   projectUUID,
		ProjectScoped: scoped,
		Total:         page.Total,
		Offset:        page.Offset,
		Limit:         limit,
		HasMore:       hasMore,
		Items:         items,
		GeneratedAt:   scanevents.FormatTime(now),
		GeneratedAtMS: scanevents.EpochMillis(now),
		Extra:         extra,
	}
}

// nonNilItems turns a nil slice (or nil) into an empty array so items/data is
// never JSON null.
func nonNilItems(items any) any {
	if items == nil {
		return []any{}
	}
	v := reflect.ValueOf(items)
	if v.Kind() == reflect.Slice && v.IsNil() {
		return reflect.MakeSlice(v.Type(), 0, 0).Interface()
	}
	return items
}

func itemCount(items any) int {
	v := reflect.ValueOf(items)
	switch v.Kind() {
	case reflect.Slice, reflect.Array:
		return v.Len()
	}
	return 0
}

// --- route contracts --------------------------------------------------------

// routeContract describes a route for the response helpers.
type routeContract struct {
	// Command is the CLI command that reads the same data. Empty when the
	// route has no CLI equivalent; the route key is reported instead.
	Command string
	// ProjectScoped reports whether the rows are filtered by X-Project-UUID.
	ProjectScoped bool
}

// restRouteContracts classifies every GET route that answers a list. The
// route-walk test (TestRouteWalkV2Lists) fails when a GET route is registered
// without being classified here or in restObjectRoutes, so a new list endpoint
// is born on the envelope.
var restRouteContracts = map[string]routeContract{
	"GET /api/findings":                     {Command: "finding", ProjectScoped: true},
	"GET /api/http-records":                 {Command: "traffic", ProjectScoped: true},
	"GET /api/scans":                        {Command: "log ls", ProjectScoped: true},
	"GET /api/scans/:uuid/logs":             {ProjectScoped: true},
	"GET /api/oast-interactions":            {ProjectScoped: true},
	"GET /api/modules":                      {Command: "module ls"},
	"GET /api/extensions":                   {Command: "extensions ls"},
	"GET /api/extensions/docs":              {Command: "extensions docs"},
	"GET /api/projects":                     {Command: "project list"},
	"GET /api/config":                       {Command: "config ls"},
	"GET /api/agent/status/list":            {ProjectScoped: true},
	"GET /api/agent/sessions":               {Command: "agent session", ProjectScoped: true},
	"GET /api/agent/sessions/:id/artifacts": {ProjectScoped: true},
	"GET /api/db/tables":                    {},
	"GET /api/db/tables/:table/columns":     {},
	"GET /api/db/tables/:table/records":     {},
}

// restObjectRoutes are the GET routes that answer a single object, a file or
// a stream; their bodies are not list-enveloped in any version.
var restObjectRoutes = map[string]bool{
	"GET /health":                             true,
	"GET /ready":                              true,
	"GET /server-info":                        true,
	"GET /metrics":                            true,
	"GET /favicon.ico":                        true,
	"GET /swagger/doc.json":                   true,
	"GET /api/info":                           true,
	"GET /api/user/info":                      true,
	"GET /api/http-records/:uuid":             true,
	"GET /api/findings/:id":                   true,
	"GET /api/stats":                          true,
	"GET /api/scans/:uuid":                    true,
	"GET /api/scan/status":                    true,
	"GET /api/scope":                          true,
	"GET /api/oast-interactions/:id":          true,
	"GET /api/extensions/:name":               true,
	"GET /api/projects/:uuid":                 true,
	"GET /api/projects/:uuid/stats":           true,
	"GET /api/agent/status/:id":               true,
	"GET /api/agent/sessions/:id":             true,
	"GET /api/agent/sessions/:id/logs":        true,
	"GET /api/agent/sessions/:id/artifacts/*": true,
	"GET /api/diagnostics":                    true,
	"GET /api/db/tables/:table/records/:id":   true,
	"GET /api/storage/source/:key":            true,
	"GET /api/storage/results/:scan_uuid":     true,
}

// routeKey names the route that is answering, "GET /api/findings/:id". Inside
// a prefix middleware (auth, project lookup) no route has matched yet, so the
// request path stands in.
func routeKey(c fiber.Ctx) string {
	method := c.Method()
	path := c.Path()
	if r := c.Route(); r != nil && r.Path != "" {
		if r.Path == path || strings.ContainsAny(r.Path, ":*") {
			path = r.Path
		}
	}
	return method + " " + path
}

func routeContractFor(c fiber.Ctx) routeContract {
	return restRouteContracts[routeKey(c)]
}

// routeCommand is the CLI-equivalent command for the route, or the route key
// when there is none.
func routeCommand(c fiber.Ctx) string {
	if cmd := routeContractFor(c).Command; cmd != "" {
		return cmd
	}
	return routeKey(c)
}
