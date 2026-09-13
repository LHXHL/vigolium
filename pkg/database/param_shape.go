package database

import (
	"net/url"
	"sort"
	"strings"
)

// DefaultMaxParamShapeSamples is the per-shape representative cap used when
// param-shape coalescing is enabled without an explicit override.
const DefaultMaxParamShapeSamples = 3

// recordURLDesc is the minimal per-record info param-shape coalescing needs. The
// stored Params (extracted insertion points, name+type+value) let us shape POST/
// PUT/PATCH and JSON bodies without the raw request body — only their content type
// and length are read alongside the URL.
type recordURLDesc struct {
	method        string
	url           string
	contentType   string
	contentLength int64
	params        []EmbeddedParam
}

// paramShapeRepresentative decides whether a record participates in param-shape
// coalescing and, if so, returns its grouping key (host + path + method + sorted
// coalescable param NAMES, values ignored) and a value signature (sorted
// name=value pairs).
//
// Coalescable params are the "same endpoint, varying values" fan-out inputs: URL
// query params (read from the URL) plus form ("body") and JSON params (read from
// the stored parameter list). Cookie/header params are auth/session churn rather
// than endpoint fan-out; path params already separate records via the path
// component of the key; xml params we don't flatten reliably — all excluded.
//
// The hard safety rule is preserved from the GET-only original: coalescing must
// never drop a request whose body we cannot fully see. A body-bearing method
// (POST/PUT/PATCH) or a non-zero request body with NO stored form/JSON params
// means there is an unseen payload that could differ between records, so the
// record is kept (coalescable=false). Multipart bodies (file uploads carry binary
// not captured as a param value) are never coalesced.
func paramShapeRepresentative(d recordURLDesc) (shapeKey, valueSig string, coalescable bool) {
	method := strings.ToUpper(strings.TrimSpace(d.method))
	u, err := url.Parse(d.url)
	if err != nil {
		return "", "", false
	}
	if strings.Contains(strings.ToLower(d.contentType), "multipart/") {
		return "", "", false
	}

	type pv struct{ key, val string }
	var collected []pv

	// u.Query() allocates a map even for an empty query; skip it when the URL
	// carries no query string (the common case for body-bearing requests).
	if u.RawQuery != "" {
		for name, vals := range u.Query() {
			sorted := append([]string(nil), vals...)
			sort.Strings(sorted)
			collected = append(collected, pv{"u:" + name, strings.Join(sorted, ",")})
		}
	}

	hasSeenBody := false
	for _, p := range d.params {
		switch p.Type {
		case "body":
			collected = append(collected, pv{"b:" + p.Name, p.Value})
			hasSeenBody = true
		case "json":
			collected = append(collected, pv{"j:" + p.Name, p.Value})
			hasSeenBody = true
		}
	}

	bodyBearing := method == "POST" || method == "PUT" || method == "PATCH"
	if (bodyBearing || d.contentLength > 0) && !hasSeenBody {
		return "", "", false // unseen body — never coalesce
	}
	if len(collected) == 0 {
		return "", "", false // nothing varies that we can key on
	}

	sort.Slice(collected, func(i, j int) bool { return collected[i].key < collected[j].key })

	const sep = "\x00"
	names := make([]string, len(collected))
	pairs := make([]string, len(collected))
	for i, c := range collected {
		names[i] = c.key
		pairs[i] = c.key + "=" + c.val
	}
	shapeKey = strings.ToLower(u.Host) + sep + u.Path + sep + method + sep + strings.Join(names, ",")
	valueSig = strings.Join(pairs, "&")
	return shapeKey, valueSig, true
}

// paramShapeCoalescer is the streaming form of coalesceUUIDsByParamShape: it
// decides record-by-record, in priority order, whether a record survives
// coalescing or is dropped as a redundant same-shape sample. State persists
// across pages so the per-shape cap applies to the whole stream, and its memory
// is bounded by the number of distinct shapes (not the number of records). Fed
// the same sequence, it makes identical keep/drop decisions to the batch helper.
type paramShapeCoalescer struct {
	maxSamples  int
	seenByShape map[string]map[string]struct{}
	dropped     int
}

// newParamShapeCoalescer returns a coalescer, or nil when coalescing is disabled
// (maxSamples <= 0); a nil coalescer keeps every record.
func newParamShapeCoalescer(maxSamples int) *paramShapeCoalescer {
	if maxSamples <= 0 {
		return nil
	}
	return &paramShapeCoalescer{
		maxSamples:  maxSamples,
		seenByShape: make(map[string]map[string]struct{}),
	}
}

// keepPlan is the result of selectKeepers: the rows that survive coalescing,
// plus the bookkeeping that must be applied for those choices to stick.
//
// Selection is separated from commitment because a page's survivors are chosen
// BEFORE its full records are fetched, and that fetch can fail. On failure the
// caller leaves the keyset unadvanced so the page is re-pulled — but if the
// choices had already been recorded, every row would look like a duplicate of
// itself on the re-pull, nothing would survive, and the caller would take its
// "whole page coalesced away" branch and step the keyset past a page it never
// served. A transient SQLITE_BUSY would silently drop those records from the scan.
//
// Commit-on-success rather than undo-on-failure: a plan that is never committed
// needs no cleanup, so a future early return between selection and commit cannot
// reintroduce that hole by forgetting to unwind.
type keepPlan struct {
	added   []shapeValue
	dropped int
}

type shapeValue struct {
	shapeKey string
	valueSig string
}

// selectKeepers decides which of rows survive coalescing WITHOUT mutating the
// coalescer. Apply the returned plan with commit once the caller has committed to
// the page. A nil coalescer keeps every row.
func (c *paramShapeCoalescer) selectKeepers(rows []riskPageRow) (surviving []string, plan keepPlan) {
	surviving = make([]string, 0, len(rows))
	if c == nil {
		for i := range rows {
			surviving = append(surviving, rows[i].UUID)
		}
		return surviving, plan
	}
	// Values chosen earlier in THIS page must be visible to later rows, or a page
	// carrying the same shape twice would keep both against a cap of one.
	pending := make(map[string]map[string]struct{}, len(rows))
	plan.added = make([]shapeValue, 0, len(rows))

	for i := range rows {
		shapeKey, valueSig, coalescable := paramShapeRepresentative(rows[i].desc())
		if !coalescable {
			surviving = append(surviving, rows[i].UUID)
			continue
		}
		committed := c.seenByShape[shapeKey]
		staged := pending[shapeKey]
		if _, dup := committed[valueSig]; dup {
			plan.dropped++
			continue
		}
		if _, dup := staged[valueSig]; dup {
			plan.dropped++
			continue
		}
		if len(committed)+len(staged) >= c.maxSamples {
			plan.dropped++
			continue
		}
		if staged == nil {
			staged = make(map[string]struct{})
			pending[shapeKey] = staged
		}
		staged[valueSig] = struct{}{}
		plan.added = append(plan.added, shapeValue{shapeKey: shapeKey, valueSig: valueSig})
		surviving = append(surviving, rows[i].UUID)
	}
	return surviving, plan
}

// commit applies a plan returned by selectKeepers, consuming its sample slots for
// the rest of the stream. A plan that is never committed leaves no trace.
func (c *paramShapeCoalescer) commit(plan keepPlan) {
	if c == nil {
		return
	}
	for _, sv := range plan.added {
		seen := c.seenByShape[sv.shapeKey]
		if seen == nil {
			seen = make(map[string]struct{})
			c.seenByShape[sv.shapeKey] = seen
		}
		seen[sv.valueSig] = struct{}{}
	}
	c.dropped += plan.dropped
}

// coalesceUUIDsByParamShape walks uuids in their given (priority) order and
// keeps at most maxSamples value-distinct representatives per param shape,
// dropping identical-value duplicates and the long tail beyond the cap. Records
// not present in descByUUID, and any request that is not a coalescable GET, are
// always kept. Order is preserved, so when the input is risk-prioritized the
// highest-value records claim the per-shape sample slots first.
//
// maxSamples <= 0 disables coalescing (returns the input unchanged).
func coalesceUUIDsByParamShape(uuids []string, descByUUID map[string]recordURLDesc, maxSamples int) (kept []string, dropped int) {
	if maxSamples <= 0 || len(uuids) == 0 {
		return uuids, 0
	}
	seenByShape := make(map[string]map[string]struct{})
	kept = make([]string, 0, len(uuids))
	for _, uuid := range uuids {
		d, ok := descByUUID[uuid]
		if !ok {
			kept = append(kept, uuid)
			continue
		}
		shapeKey, valueSig, coalescable := paramShapeRepresentative(d)
		if !coalescable {
			kept = append(kept, uuid)
			continue
		}
		seen := seenByShape[shapeKey]
		if seen == nil {
			seen = make(map[string]struct{})
			seenByShape[shapeKey] = seen
		}
		if _, dup := seen[valueSig]; dup {
			dropped++ // identical query values as an already-kept representative
			continue
		}
		if len(seen) >= maxSamples {
			dropped++ // per-shape sample cap reached
			continue
		}
		seen[valueSig] = struct{}{}
		kept = append(kept, uuid)
	}
	return kept, dropped
}
