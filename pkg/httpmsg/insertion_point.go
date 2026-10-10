package httpmsg

// insertion_point.go - Insertion point system for payload injection
//
// Implementations are in separate files:
//   - insertion_point_simple.go: SimpleInsertionPoint (basic byte replacement)
//   - insertion_point_param.go: ParameterInsertionPoint (parameter-aware with encoding)
//   - insertion_point_encoded.go: EncodedInsertionPoint (custom encoder support)

import (
	"bytes"
	"slices"
	"sort"
)

// InsertionPointType represents where payload injection occurs in an HTTP request.
type InsertionPointType byte

const (
	INS_PARAM_URL            InsertionPointType = 0   // URL parameter value
	INS_PARAM_BODY           InsertionPointType = 1   // POST body parameter value
	INS_PARAM_COOKIE         InsertionPointType = 2   // Cookie value
	INS_PARAM_XML            InsertionPointType = 3   // XML element value
	INS_PARAM_XML_ATTR       InsertionPointType = 4   // XML attribute value
	INS_PARAM_MULTIPART_ATTR InsertionPointType = 5   // Multipart attribute value
	INS_PARAM_JSON           InsertionPointType = 6   // JSON value
	INS_PARAM_AMF            InsertionPointType = 7   // AMF parameter
	INS_HEADER               InsertionPointType = 32  // HTTP header value
	INS_URL_PATH_FOLDER      InsertionPointType = 33  // REST URL path folder
	INS_PARAM_NAME_URL       InsertionPointType = 34  // URL parameter name
	INS_PARAM_NAME_BODY      InsertionPointType = 35  // Body parameter name
	INS_ENTIRE_BODY          InsertionPointType = 36  // Entire request body
	INS_URL_PATH_FILENAME    InsertionPointType = 37  // REST URL path filename
	INS_USER_PROVIDED        InsertionPointType = 64  // User-defined position
	INS_EXTENSION_PROVIDED   InsertionPointType = 65  // Extension-provided position
	INS_UNKNOWN              InsertionPointType = 127 // Unknown/unclassified
)

// String returns a human-readable name for the insertion point type.
func (t InsertionPointType) String() string {
	switch t {
	case INS_PARAM_URL:
		return "URL_PARAM"
	case INS_PARAM_BODY:
		return "BODY_PARAM"
	case INS_PARAM_COOKIE:
		return "COOKIE"
	case INS_PARAM_XML:
		return "XML_PARAM"
	case INS_PARAM_XML_ATTR:
		return "XML_ATTR"
	case INS_PARAM_MULTIPART_ATTR:
		return "MULTIPART_ATTR"
	case INS_PARAM_JSON:
		return "JSON_PARAM"
	case INS_PARAM_AMF:
		return "AMF_PARAM"
	case INS_HEADER:
		return "HEADER"
	case INS_URL_PATH_FOLDER:
		return "PATH_FOLDER"
	case INS_PARAM_NAME_URL:
		return "PARAM_NAME_URL"
	case INS_PARAM_NAME_BODY:
		return "PARAM_NAME_BODY"
	case INS_ENTIRE_BODY:
		return "ENTIRE_BODY"
	case INS_URL_PATH_FILENAME:
		return "PATH_FILENAME"
	case INS_USER_PROVIDED:
		return "USER_PROVIDED"
	case INS_EXTENSION_PROVIDED:
		return "EXTENSION_PROVIDED"
	case INS_UNKNOWN:
		return "UNKNOWN"
	default:
		return "UNKNOWN"
	}
}

// InsertionPoint interface defines how to inject payloads into HTTP requests.
//
// Methods:
// - Name(): Returns the name/identifier (e.g., parameter name)
// - BaseValue(): Returns the original value before payload injection
// - Type(): Returns the insertion point type constant
// - BuildRequest(): Creates new request with payload injected
// - PayloadOffsets(): Returns byte offsets of payload in built request
type InsertionPoint interface {
	// Name returns the name of this insertion point.
	// For parameters: returns parameter name (e.g., "id", "username")
	// For custom points: returns user-defined name
	Name() string

	// BaseValue returns the original value at this insertion point.
	// For parameters: returns original parameter value
	// For custom points: returns bytes at original position
	BaseValue() string

	// Type returns the type constant for this insertion point.
	// Returns one of the INS_* constants
	Type() InsertionPointType

	// BuildRequest creates a new HTTP request with the payload injected.
	//
	// Algorithm:
	// 1. Take base request bytes
	// 2. Replace insertion point value with payload
	// 3. Apply appropriate encoding (URL encoding, etc.)
	// 4. Update Content-Length if needed
	// 5. Return modified request
	BuildRequest(payload []byte) []byte

	// PayloadOffsets returns the byte offsets of the payload in the built request.
	//
	// This allows scanners to locate the payload position after request is built.
	// Useful for response analysis to map responses back to specific payloads.
	PayloadOffsets(payload []byte) []int
}

// CreateAllInsertionPoints creates insertion points with optional nested discovery.
//
// This is the main factory function for creating insertion points:
// 1. Extract all parameters from request (URL, body, cookies, headers, etc.)
// 2. Create standard insertion points for each parameter
// 3. Optionally detect and create nested insertion points (JSON in params, etc.)
//
// The includeNested parameter controls nested structure scanning:
//   - false: Only scan direct parameter values (faster, less thorough)
//   - true: Also scan nested structures like JSON/XML/Base64 (slower, more thorough)
//
// Algorithm:
//  1. Call AnalyzeRequest() to extract all parameters
//  2. Create ParameterInsertionPoint for each parameter
//  3. If includeNested == true:
//     a. Call DiscoverNestedInsertionPoints() with all parameters
//     b. Append discovered nested IPs to results
//  4. Return complete list of insertion points
//
// Example workflow:
//
//	request := []byte("GET /api?data={\"user\":\"admin\"} HTTP/1.1\r\n\r\n")
//	points, _ := CreateAllInsertionPoints(request, true)
//	// Returns:
//	//   1. ParameterInsertionPoint for "data" parameter
//	//   2. NestedInsertionPoint for "user" within JSON (if includeNested=true)
//
// Parameters:
//   - request: Complete HTTP request bytes
//   - includeNested: Whether to detect and create nested insertion points
//
// Returns:
//   - List of InsertionPoint interfaces (standard + nested if enabled)
//   - Error if request analysis fails
func CreateAllInsertionPoints(request []byte, includeNested bool) ([]InsertionPoint, error) {
	return createInsertionPoints(request, InsertionPointOptions{IncludeNested: includeNested})
}

// createInsertionPoints is the factory behind CreateAllInsertionPoints and
// CreateInsertionPoints. With no extras selected in o it builds exactly the
// CreateAllInsertionPoints set; the opt-in points (parameter names, entire
// body, new parameter) are appended before the priority sort, which ranks them
// after every parameter value (insertionPointPriority's default bucket).
func createInsertionPoints(request []byte, o InsertionPointOptions) ([]InsertionPoint, error) {
	includeNested := o.IncludeNested

	// Step 1: Analyze request to extract all parameters
	info, err := AnalyzeRequest(request)
	if err != nil {
		return nil, err
	}

	// Single clone shared across all insertion points from this call, along with
	// the Content-Length layout they all resolve against.
	// BuildRequest() never mutates baseRequest (it allocates a new result slice),
	// so sharing without synchronization is safe.
	shared := newSharedBaseRequest(bytes.Clone(request))

	// Step 2: Create standard insertion points for each parameter
	points := make([]InsertionPoint, 0, len(info.Parameters))

	for _, param := range info.Parameters {
		ip := newParameterInsertionPointShared(shared, param)
		points = append(points, ip)
	}

	// Step 3: Optionally discover and create nested insertion points
	if includeNested {
		nestedIPs := discoverNestedInsertionPointsShared(shared, info.Parameters)
		points = slices.Grow(points, len(nestedIPs))
		for _, nip := range nestedIPs {
			points = append(points, nip)
		}
	}

	// Step 4: Create header insertion points for injectable headers
	// This enables modules to test header injection vectors (SQLi via X-Forwarded-For,
	// SSRF via Referer, SSTI via User-Agent, etc.). Synthetic headers are added when
	// not already present. Modules filter via AllowedInsertionPointTypes().
	headerIPs := createHeaderInsertionPoints(shared, info.Headers)
	// Bound the header fan-out: a request with an unusually large header block would
	// otherwise multiply every whole-request module's work without adding real
	// coverage. The cap is generous enough never to trim a normal browser request.
	if len(headerIPs) > maxHeaderInsertionPoints {
		headerIPs = headerIPs[:maxHeaderInsertionPoints]
	}
	points = append(points, headerIPs...)

	// Step 5: opt-in points (CreateInsertionPoints only).
	points = append(points, extraInsertionPoints(shared, info.Parameters, o)...)

	// Order by likelihood of carrying an application injection sink so whole-request
	// modules (which loop over every point in a single call) test the high-value
	// points first: query params, then body params, then cookies, then headers.
	// This front-loading matters under a per-module timeout — an early-tested,
	// already-confirmed finding survives even if the tail of the loop is cut short.
	// The sort is stable, so each group keeps its original in-request order.
	sort.SliceStable(points, func(i, j int) bool {
		return insertionPointPriority(points[i].Type()) < insertionPointPriority(points[j].Type())
	})

	return points, nil
}

// maxHeaderInsertionPoints bounds how many request headers become insertion points
// for a single request (see CreateAllInsertionPoints).
const maxHeaderInsertionPoints = 64

// insertionPointPriority ranks insertion-point types by how likely the position is
// to reach an application injection sink, lowest first: query params (0), body
// params (1), cookies (2), any other type — path/entire-body/custom — (3), then
// request headers last (4). Whole-request modules test points in this order so the
// highest-value ones run within any time budget.
func insertionPointPriority(t InsertionPointType) int {
	switch t {
	case INS_PARAM_URL:
		return 0
	case INS_PARAM_BODY, INS_PARAM_JSON, INS_PARAM_XML, INS_PARAM_XML_ATTR, INS_PARAM_MULTIPART_ATTR, INS_PARAM_AMF:
		return 1
	case INS_PARAM_COOKIE:
		return 2
	case INS_HEADER:
		return 4
	default:
		return 3
	}
}

// InsertionPointRequiresContentLengthUpdate returns whether an insertion point type
// requires Content-Length header updates when modifying request body.
//
// Body parameters need updates because they modify request body length:
//   - INS_PARAM_BODY: POST body parameters
//   - INS_PARAM_XML: XML elements
//   - INS_PARAM_XML_ATTR: XML attributes
//   - INS_PARAM_MULTIPART_ATTR: Multipart attributes
//   - INS_PARAM_JSON: JSON values
//   - INS_ENTIRE_BODY: Entire body
//
// URL/Cookie/Path parameters don't need updates because they don't affect body length.
func InsertionPointRequiresContentLengthUpdate(ipType InsertionPointType) bool {
	switch ipType {
	case INS_PARAM_BODY,
		INS_PARAM_XML,
		INS_PARAM_XML_ATTR,
		INS_PARAM_MULTIPART_ATTR,
		INS_PARAM_JSON,
		INS_ENTIRE_BODY:
		return true
	default:
		return false
	}
}
