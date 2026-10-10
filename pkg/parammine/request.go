package parammine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// builder places parameter pairs into copies of the base request.
type builder struct {
	base *httpmsg.HttpRequestResponse
	loc  Location
	// existing holds the parameter names the base request already carries in
	// the chosen location; they are never mined.
	existing map[string]bool
	// jsonBody is the decoded base body for LocationJSON.
	jsonBody map[string]json.RawMessage
}

// ParseLocation validates a user-supplied location; "" and "auto" mean pick
// from the request.
func ParseLocation(s string) (Location, error) {
	switch Location(strings.ToLower(strings.TrimSpace(s))) {
	case "", "auto":
		return "", nil
	case LocationQuery, "url", "get":
		return LocationQuery, nil
	case LocationForm, "body", "post":
		return LocationForm, nil
	case LocationJSON:
		return LocationJSON, nil
	}
	return "", fmt.Errorf("unknown parameter location %q (want query, form, json or auto)", s)
}

// DetectLocation picks where to put mined names for a request: the query
// string for bodiless methods and multipart bodies, the JSON object for a JSON
// body, the form body otherwise.
func DetectLocation(req *httpmsg.HttpRequest) Location {
	switch strings.ToUpper(req.Method()) {
	case "GET", "HEAD", "DELETE", "OPTIONS":
		return LocationQuery
	}
	ct := strings.ToLower(req.Header("Content-Type"))
	switch {
	case strings.Contains(ct, "json"):
		return LocationJSON
	case strings.Contains(ct, "multipart/"):
		return LocationQuery
	case ct == "" || strings.Contains(ct, "x-www-form-urlencoded"):
		return LocationForm
	}
	return LocationQuery
}

func newBuilder(base *httpmsg.HttpRequestResponse, loc Location) (*builder, error) {
	req := base.Request()
	if loc == "" {
		loc = DetectLocation(req)
	}
	b := &builder{base: base, loc: loc, existing: make(map[string]bool)}
	switch loc {
	case LocationQuery:
		if _, q, ok := strings.Cut(req.Path(), "?"); ok {
			if vals, err := url.ParseQuery(q); err == nil {
				for k := range vals {
					b.existing[k] = true
				}
			}
		}
	case LocationForm:
		if vals, err := url.ParseQuery(string(req.Body())); err == nil {
			for k := range vals {
				b.existing[k] = true
			}
		}
	case LocationJSON:
		b.jsonBody = map[string]json.RawMessage{}
		if body := bytes.TrimSpace(req.Body()); len(body) > 0 {
			if err := json.Unmarshal(body, &b.jsonBody); err != nil {
				return nil, fmt.Errorf("parammine: JSON location needs a JSON object body: %w", err)
			}
		}
		for k := range b.jsonBody {
			b.existing[k] = true
		}
	default:
		return nil, fmt.Errorf("parammine: unknown location %q", loc)
	}
	return b, nil
}

// filterExisting drops names the base request already sends.
func (b *builder) filterExisting(words []string) []string {
	out := make([]string, 0, len(words))
	for _, w := range words {
		if !b.existing[w] {
			out = append(out, w)
		}
	}
	return out
}

// build returns a copy of the base request carrying pairs.
func (b *builder) build(pairs []pair) (*httpmsg.HttpRequestResponse, error) {
	req := b.base.Request()
	switch b.loc {
	case LocationQuery:
		path := req.Path()
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
			if strings.HasSuffix(path, "?") || strings.HasSuffix(path, "&") {
				sep = ""
			}
		}
		req = req.WithPath(path + sep + encodePairs(pairs))
	case LocationForm:
		body := req.Body()
		var buf bytes.Buffer
		buf.Write(body)
		if len(body) > 0 && !bytes.HasSuffix(body, []byte("&")) {
			buf.WriteByte('&')
		}
		buf.WriteString(encodePairs(pairs))
		if req.Header("Content-Type") == "" {
			req = req.WithHeader("Content-Type", "application/x-www-form-urlencoded")
		}
		req = req.WithBody(buf.Bytes())
	case LocationJSON:
		obj := make(map[string]json.RawMessage, len(b.jsonBody)+len(pairs))
		for k, v := range b.jsonBody {
			obj[k] = v
		}
		for _, p := range pairs {
			v, _ := json.Marshal(p.value)
			obj[p.name] = v
		}
		body, err := json.Marshal(obj)
		if err != nil {
			return nil, err
		}
		if req.Header("Content-Type") == "" {
			req = req.WithHeader("Content-Type", "application/json")
		}
		req = req.WithBody(body)
	}
	return httpmsg.NewHttpRequestResponse(req, nil), nil
}

func encodePairs(pairs []pair) string {
	var sb strings.Builder
	for i, p := range pairs {
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString(url.QueryEscape(p.name))
		sb.WriteByte('=')
		sb.WriteString(url.QueryEscape(p.value))
	}
	return sb.String()
}

// pairCost is how many bytes one name adds to a request in this location.
func (b *builder) pairCost(name string) int {
	switch b.loc {
	case LocationJSON:
		return len(name) + canaryLen + 6 // "name":"value",
	default:
		return len(url.QueryEscape(name)) + canaryLen + 2 // &name=value
	}
}

// chunk splits names into groups that fit the location's transport budget and
// the per-chunk name cap. A name too long to fit even alone is dropped.
func (b *builder) chunk(names []string, cfg Config) [][]string {
	req := b.base.Request()
	limit, used := cfg.MaxBodyBytes, len(req.Body())
	if b.loc == LocationQuery {
		limit, used = cfg.MaxQueryBytes, len(req.Path())
	}
	room := limit - used
	var out [][]string
	var cur []string
	size := 0
	for _, n := range names {
		c := b.pairCost(n)
		if c > room {
			continue
		}
		if len(cur) > 0 && (size+c > room || len(cur) >= cfg.MaxNamesPerChunk) {
			out = append(out, cur)
			cur, size = nil, 0
		}
		cur = append(cur, n)
		size += c
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}
