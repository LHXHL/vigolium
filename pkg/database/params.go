package database

import (
	"context"
	"hash/fnv"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/internal/redact"
	"github.com/vigolium/vigolium/pkg/mutation"
)

// The parameter inventory (`vigolium params`): one row per (endpoint,
// location, name), with a value-type histogram from mutation.Classify. It
// shares the endpoint inventory's light-record stream and endpoint key, so a
// ParamView's endpoint_id is the EndpointView id of the same endpoint.

const (
	// paramClassifyCap bounds the values classified per parameter, so a huge
	// corpus costs bounded CPU; Types then describes a sample of that size.
	paramClassifyCap = 200
	// paramDistinctCap bounds the distinct values tracked per parameter.
	paramDistinctCap = 1000
	paramSamples     = 3
	paramSampleLen   = 64
	// DefaultMaxParams bounds the distinct parameters one aggregate holds.
	DefaultMaxParams = 200000
)

// ParamOptions shapes a Params call.
type ParamOptions struct {
	// Endpoint keeps one endpoint, by EndpointView id or by template.
	Endpoint string
	// Locations keeps these locations (query, body, json, cookie, xml,
	// multipart, path, header, other).
	Locations []string
	// Types keeps parameters whose dominant type is listed (ValueType names:
	// integer, uuid, sequential_id, email, jwt, …).
	Types []string
	// MinOccurrences drops parameters seen fewer times.
	MinOccurrences int64
	// ShowValues disables sample redaction.
	ShowValues bool
	// Limit/Offset page the list; Limit 0 returns every parameter.
	Limit, Offset int
	// MaxParams overrides DefaultMaxParams (0 = default).
	MaxParams int
}

// ParamView is one parameter of one endpoint.
type ParamView struct {
	EndpointID string   `json:"endpoint_id"`
	Origin     string   `json:"origin"`
	Template   string   `json:"template"`
	Methods    []string `json:"methods"`
	Location   string   `json:"location"`
	Name       string   `json:"name"`
	// After is the literal segment before a path parameter ("users" for
	// {int}@1 in /users/{int}).
	After string `json:"after,omitempty"`

	Occurrences    int64 `json:"occurrences"`
	DistinctValues int64 `json:"distinct_values"`
	DistinctCapped bool  `json:"distinct_capped"`

	// Types is a histogram of mutation.Classify over at most 200 values;
	// Classified says how many were classified.
	Types        map[string]int64 `json:"types"`
	Classified   int64            `json:"classified"`
	DominantType string           `json:"dominant_type"`

	// Samples are up to three values, at most 64 characters each. Cookie and
	// header values and secret-looking names are redacted unless ShowValues.
	Samples  []string `json:"samples"`
	Redacted bool     `json:"redacted,omitempty"`
}

// ParamResult is a bounded parameter inventory.
type ParamResult struct {
	Params            []ParamView
	Total             int64
	RecordsScanned    int64
	Capped            bool
	UnbucketedRecords int64
}

type paramAcc struct {
	endpointID, origin, template string
	location, name, after        string
	methods                      map[string]struct{}
	occurrences                  int64
	distinct                     map[uint64]struct{}
	distinctCapped               bool
	types                        map[string]int64
	classified                   int64
	samples                      []string
	redacted                     bool
}

func (a *paramAcc) observe(method, value string, showValues bool) {
	a.occurrences++
	a.methods[strings.ToUpper(method)] = struct{}{}
	h := fnv.New64a()
	_, _ = h.Write([]byte(value))
	sum := h.Sum64()
	if _, ok := a.distinct[sum]; !ok {
		if len(a.distinct) >= paramDistinctCap {
			a.distinctCapped = true
		} else {
			a.distinct[sum] = struct{}{}
			if len(a.samples) < paramSamples && value != "" {
				if a.redacted && !showValues {
					if len(a.samples) == 0 {
						a.samples = append(a.samples, redact.Placeholder)
					}
				} else {
					a.samples = append(a.samples, truncateSample(value))
				}
			}
		}
	}
	if a.classified < paramClassifyCap {
		a.classified++
		hint := &mutation.SchemaHint{ParamName: a.name}
		if a.location == "path" {
			hint.ParamName = a.after
		}
		a.types[classifyParamValue(value, hint, a.location == "path").String()]++
	}
}

// classifyParamValue is mutation.Classify plus the rule shared with
// pathshape: in a path segment "0"/"1" are integers (ids), not booleans. A
// query or body "debug=1" keeps Classify's answer.
func classifyParamValue(value string, hint *mutation.SchemaHint, inPath bool) mutation.ValueType {
	t := mutation.Classify(value, hint)
	if inPath && t == mutation.TypeBoolean && (value == "0" || value == "1") {
		return mutation.TypeInteger
	}
	return t
}

func truncateSample(v string) string {
	if len(v) <= paramSampleLen {
		return v
	}
	// Cut on a rune boundary.
	cut := paramSampleLen
	for cut > 0 && !utf8RuneStart(v[cut]) {
		cut--
	}
	return v[:cut] + "…"
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }

// paramRedacted reports whether a parameter's values are hidden by default:
// cookies and headers always, any location when the name reads as a secret.
func paramRedacted(location, name string) bool {
	return location == "cookie" || location == "header" || redact.IsSensitiveName(name)
}

func (a *paramAcc) view() ParamView {
	v := ParamView{
		EndpointID:     a.endpointID,
		Origin:         a.origin,
		Template:       a.template,
		Methods:        sortedSetKeys(a.methods),
		Location:       a.location,
		Name:           a.name,
		After:          a.after,
		Occurrences:    a.occurrences,
		DistinctValues: int64(len(a.distinct)),
		DistinctCapped: a.distinctCapped,
		Types:          a.types,
		Classified:     a.classified,
		Samples:        append([]string{}, a.samples...),
		Redacted:       a.redacted,
	}
	var best int64 = -1
	for t, n := range a.types {
		if n > best || (n == best && t < v.DominantType) {
			best, v.DominantType = n, t
		}
	}
	return v
}

// Params aggregates the filtered records into a parameter inventory.
func (qb *QueryBuilder) Params(ctx context.Context, opts ParamOptions) (ParamResult, error) {
	maxParams := opts.MaxParams
	if maxParams <= 0 {
		maxParams = DefaultMaxParams
	}
	locations := map[string]bool{}
	for _, l := range opts.Locations {
		if l = strings.ToLower(strings.TrimSpace(l)); l != "" {
			locations[l] = true
		}
	}
	types := map[string]bool{}
	for _, t := range opts.Types {
		if t = strings.ToLower(strings.TrimSpace(t)); t != "" {
			types[t] = true
		}
	}
	wantLoc := func(l string) bool { return len(locations) == 0 || locations[l] }

	var res ParamResult
	accs := map[string]*paramAcc{}
	get := func(origin, template, loc, name, after string) *paramAcc {
		key := origin + " " + template + "\x00" + loc + "\x00" + name
		if a := accs[key]; a != nil {
			return a
		}
		if len(accs) >= maxParams {
			res.Capped = true
			return nil
		}
		a := &paramAcc{
			endpointID: EndpointID(origin, template), origin: origin, template: template,
			location: loc, name: name, after: after,
			methods: map[string]struct{}{}, distinct: map[uint64]struct{}{},
			types: map[string]int64{}, redacted: paramRedacted(loc, name),
		}
		accs[key] = a
		return a
	}

	seen, err := qb.forEachInventoryRecord(ctx, func(r *inventoryRecord) {
		origin := EndpointOrigin(r.Scheme, r.Hostname, r.Port)
		template, segments, kinds := EndpointTemplate(r.Path)
		if opts.Endpoint != "" && opts.Endpoint != template && opts.Endpoint != EndpointID(origin, template) {
			return
		}
		dropped := false
		for _, p := range r.Parameters {
			loc := paramLocation(p.Type)
			if loc == "path" || !wantLoc(loc) || p.Name == "" {
				continue
			}
			if a := get(origin, template, loc, p.Name, ""); a != nil {
				a.observe(r.Method, p.Value, opts.ShowValues)
			} else {
				dropped = true
			}
		}
		if wantLoc("path") {
			for i, k := range kinds {
				if !k.Dynamic() || i >= len(segments) {
					continue
				}
				after := ""
				if i > 0 && !kinds[i-1].Dynamic() {
					after = segments[i-1]
				}
				if a := get(origin, template, "path", pathParamName(k, i), after); a != nil {
					a.observe(r.Method, segments[i], opts.ShowValues)
				} else {
					dropped = true
				}
			}
		}
		if dropped {
			res.UnbucketedRecords++
		}
	})
	if err != nil {
		return ParamResult{}, err
	}
	res.RecordsScanned = seen

	views := make([]ParamView, 0, len(accs))
	for _, a := range accs {
		if a.occurrences < opts.MinOccurrences {
			continue
		}
		v := a.view()
		if len(types) > 0 && !types[v.DominantType] {
			continue
		}
		views = append(views, v)
	}
	sort.SliceStable(views, func(i, j int) bool {
		a, b := views[i], views[j]
		if a.Origin != b.Origin {
			return a.Origin < b.Origin
		}
		if a.Template != b.Template {
			return a.Template < b.Template
		}
		if a.Occurrences != b.Occurrences {
			return a.Occurrences > b.Occurrences
		}
		if a.Location != b.Location {
			return a.Location < b.Location
		}
		return a.Name < b.Name
	})
	res.Total = int64(len(views))
	res.Params = pageSlice(views, opts.Offset, opts.Limit)
	return res, nil
}

// ParamValueTypes lists the dominant_type names --type accepts.
func ParamValueTypes() []string {
	var out []string
	for t := mutation.TypeUnknown; t <= mutation.TypeEmpty; t++ {
		out = append(out, t.String())
	}
	return out
}
