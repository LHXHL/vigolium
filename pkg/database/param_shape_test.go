package database

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestParamShapeRepresentative(t *testing.T) {
	cases := []struct {
		name        string
		desc        recordURLDesc
		coalescable bool
		wantSameKey *recordURLDesc // optional: another record whose shape key should match
	}{
		{"get with query is coalescable", recordURLDesc{method: "GET", url: "https://a.com/search?q=1"}, true,
			&recordURLDesc{method: "GET", url: "https://a.com/search?q=2"}},
		{"get without query is not", recordURLDesc{method: "GET", url: "https://a.com/about"}, false, nil},
		{"post with unseen body is not coalescable", recordURLDesc{method: "POST", url: "https://a.com/search?q=1"}, false, nil},
		{"put with unseen body is not coalescable", recordURLDesc{method: "PUT", url: "https://a.com/x?a=1"}, false, nil},
		{"method case insensitive", recordURLDesc{method: "get", url: "https://a.com/s?x=1"}, true, nil},
		// POST whose form body shape is visible via stored params IS coalescable.
		{"post with form body is coalescable",
			recordURLDesc{method: "POST", url: "https://a.com/login", contentType: "application/x-www-form-urlencoded",
				params: []EmbeddedParam{{Name: "user", Value: "a", Type: "body"}, {Name: "pass", Value: "1", Type: "body"}}},
			true,
			&recordURLDesc{method: "POST", url: "https://a.com/login", contentType: "application/x-www-form-urlencoded",
				params: []EmbeddedParam{{Name: "user", Value: "b", Type: "body"}, {Name: "pass", Value: "2", Type: "body"}}}},
		// JSON body shape via stored json params.
		{"post with json body is coalescable",
			recordURLDesc{method: "POST", url: "https://a.com/api", contentType: "application/json",
				params: []EmbeddedParam{{Name: "name", Value: "x", Type: "json"}}},
			true, nil},
		// Multipart (file-upload risk) is never coalesced even with body params.
		{"multipart is not coalescable",
			recordURLDesc{method: "POST", url: "https://a.com/upload", contentType: "multipart/form-data; boundary=z",
				params: []EmbeddedParam{{Name: "file", Value: "x", Type: "body"}}},
			false, nil},
		// A body-bearing content length with no visible params is an unseen body.
		{"non-zero body with no params is not coalescable",
			recordURLDesc{method: "POST", url: "https://a.com/x", contentLength: 42}, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, _, coalescable := paramShapeRepresentative(tc.desc)
			if coalescable != tc.coalescable {
				t.Fatalf("coalescable = %v, want %v", coalescable, tc.coalescable)
			}
			if tc.wantSameKey != nil {
				key2, _, _ := paramShapeRepresentative(*tc.wantSameKey)
				if key != key2 {
					t.Errorf("shape keys differ for value-only-different records: %q vs %q", key, key2)
				}
			}
		})
	}
}

func TestParamShapeRepresentative_DistinguishesShapes(t *testing.T) {
	rep := func(method, rawURL string) (string, string, bool) {
		return paramShapeRepresentative(recordURLDesc{method: method, url: rawURL})
	}
	// Different param-name sets => different shape keys.
	k1, _, _ := rep("GET", "https://a.com/p?id=1")
	k2, _, _ := rep("GET", "https://a.com/p?id=1&debug=1")
	if k1 == k2 {
		t.Error("different param-name sets must produce different shape keys")
	}
	// Same names, different order => same key; value differences => same key.
	k3, v3, _ := rep("GET", "https://a.com/p?a=1&b=2")
	k4, v4, _ := rep("GET", "https://a.com/p?b=9&a=8")
	if k3 != k4 {
		t.Error("param order must not affect the shape key")
	}
	if v3 == v4 {
		t.Error("different values must produce different value signatures")
	}
	// Different host or path => different shape.
	k5, _, _ := rep("GET", "https://b.com/p?a=1")
	if k3 == k5 {
		t.Error("different host must produce a different shape key")
	}
	// Same path+params but different method => different shape (GET ?a=1 vs a
	// form POST with a body param a) must not collapse together.
	getKey, _, _ := rep("GET", "https://a.com/r?a=1")
	postKey, _, postOK := paramShapeRepresentative(recordURLDesc{
		method: "POST", url: "https://a.com/r", contentType: "application/x-www-form-urlencoded",
		params: []EmbeddedParam{{Name: "a", Value: "1", Type: "body"}},
	})
	if !postOK || getKey == postKey {
		t.Error("different methods must produce different shape keys")
	}
}

func TestCoalesceUUIDsByParamShape(t *testing.T) {
	desc := map[string]recordURLDesc{
		// Same shape /search?q=*, 5 value-distinct GETs.
		"u1": {method: "GET", url: "https://a.com/search?q=1"},
		"u2": {method: "GET", url: "https://a.com/search?q=2"},
		"u3": {method: "GET", url: "https://a.com/search?q=3"},
		"u4": {method: "GET", url: "https://a.com/search?q=4"},
		"u5": {method: "GET", url: "https://a.com/search?q=1"}, // identical value to u1
		// A different shape (extra param) — kept independently.
		"u6": {method: "GET", url: "https://a.com/search?q=1&page=2"},
		// A POST — never coalesced.
		"u7": {method: "POST", url: "https://a.com/search?q=1"},
		// A param-less GET — never coalesced.
		"u8": {method: "GET", url: "https://a.com/about"},
		// Unknown UUID (not in desc) — always kept.
	}
	uuids := []string{"u1", "u2", "u3", "u4", "u5", "u6", "u7", "u8", "unknown"}

	kept, dropped := coalesceUUIDsByParamShape(uuids, desc, 3)

	// u1,u2,u3 kept (3 value-distinct); u4 dropped (cap); u5 dropped (dup of u1).
	// u6 (distinct shape), u7 (POST), u8 (no query), unknown all kept.
	wantKept := map[string]bool{"u1": true, "u2": true, "u3": true, "u6": true, "u7": true, "u8": true, "unknown": true}
	if len(kept) != len(wantKept) {
		t.Fatalf("kept = %v, want %d entries", kept, len(wantKept))
	}
	for _, k := range kept {
		if !wantKept[k] {
			t.Errorf("unexpected kept uuid %q", k)
		}
	}
	if dropped != 2 {
		t.Errorf("dropped = %d, want 2 (u4 cap + u5 dup)", dropped)
	}

	// Order is preserved.
	if kept[0] != "u1" || kept[1] != "u2" || kept[2] != "u3" {
		t.Errorf("order not preserved: %v", kept)
	}
}

func TestCoalesceUUIDsByParamShape_Disabled(t *testing.T) {
	desc := map[string]recordURLDesc{
		"u1": {method: "GET", url: "https://a.com/s?q=1"},
		"u2": {method: "GET", url: "https://a.com/s?q=2"},
	}
	uuids := []string{"u1", "u2"}
	kept, dropped := coalesceUUIDsByParamShape(uuids, desc, 0)
	if len(kept) != 2 || dropped != 0 {
		t.Errorf("maxSamples=0 must be a no-op, got kept=%v dropped=%d", kept, dropped)
	}
}

func TestCoalesceUUIDsByParamShape_PriorityOrderWins(t *testing.T) {
	// When the input is in priority order, the first (highest-priority) samples
	// claim the cap. Here u_hi appears before the lower-priority same-value u_lo.
	desc := map[string]recordURLDesc{
		"hi": {method: "GET", url: "https://a.com/s?q=1"},
		"lo": {method: "GET", url: "https://a.com/s?q=1"}, // same value
	}
	kept, dropped := coalesceUUIDsByParamShape([]string{"hi", "lo"}, desc, 3)
	if len(kept) != 1 || kept[0] != "hi" || dropped != 1 {
		t.Errorf("priority record must win the slot, got kept=%v dropped=%d", kept, dropped)
	}
}

// searchShapePage is one page of rows sharing a param shape, differing by value.
func searchShapePage(values ...string) []riskPageRow {
	rows := make([]riskPageRow, 0, len(values))
	for _, v := range values {
		rows = append(rows, riskPageRow{
			UUID:   "uuid-" + v,
			Method: "GET",
			URL:    "https://a.com/search?q=" + v,
		})
	}
	return rows
}

// TestSelectKeepersDoesNotMutateUntilCommit is the regression guard for the
// silent page drop: survivors are chosen before the full-record fetch, so an
// uncommitted selection must leave no trace. When the choices were recorded
// eagerly, the re-pull after a failed fetch saw every row as a duplicate of
// itself, kept nothing, and the caller stepped the keyset past a page it never
// served.
func TestSelectKeepersDoesNotMutateUntilCommit(t *testing.T) {
	c := newParamShapeCoalescer(5)

	first, plan := c.selectKeepers(searchShapePage("1", "2", "3"))
	if len(first) != 3 {
		t.Fatalf("first pass: want 3 survivors, got %d (%v)", len(first), first)
	}
	// The fetch failed, so the plan is discarded rather than committed.
	if c.dropped != 0 || len(c.seenByShape) != 0 {
		t.Errorf("selection mutated the coalescer: dropped=%d shapes=%d", c.dropped, len(c.seenByShape))
	}
	_ = plan

	// Re-pulling the same page must reproduce the same survivors.
	retry, retryPlan := c.selectKeepers(searchShapePage("1", "2", "3"))
	if len(retry) != len(first) {
		t.Fatalf("after a discarded plan: want %d survivors on retry, got %d (%v)", len(first), len(retry), retry)
	}
	for i := range first {
		if retry[i] != first[i] {
			t.Errorf("retry survivor %d = %q, want %q", i, retry[i], first[i])
		}
	}

	// Committing makes the choices stick for the rest of the stream.
	c.commit(retryPlan)
	if len(c.seenByShape) != 1 {
		t.Errorf("commit recorded %d shapes, want 1", len(c.seenByShape))
	}
}

// A committed page consumes its shape's sample slots, so a later page of the
// same shape coalesces away.
func TestCommitConsumesSampleSlots(t *testing.T) {
	c := newParamShapeCoalescer(3)

	kept, plan := c.selectKeepers(searchShapePage("1", "2", "3"))
	if len(kept) != 3 {
		t.Fatalf("first page: want 3 survivors, got %d", len(kept))
	}
	c.commit(plan)

	kept, plan = c.selectKeepers(searchShapePage("4", "5"))
	if len(kept) != 0 {
		t.Fatalf("second page: want 0 survivors past the cap, got %d (%v)", len(kept), kept)
	}
	c.commit(plan)
	if c.dropped != 2 {
		t.Errorf("dropped = %d, want 2", c.dropped)
	}
}

// Rows sharing a shape WITHIN one page must respect the cap between themselves,
// not just against already-committed state.
func TestSelectKeepersAppliesCapWithinOnePage(t *testing.T) {
	c := newParamShapeCoalescer(2)
	kept, _ := c.selectKeepers(searchShapePage("1", "2", "3", "4"))
	if len(kept) != 2 {
		t.Errorf("want 2 survivors under a cap of 2, got %d (%v)", len(kept), kept)
	}
}

// A duplicate value inside one page is dropped even before commit.
func TestSelectKeepersDropsIntraPageDuplicates(t *testing.T) {
	c := newParamShapeCoalescer(5)
	kept, plan := c.selectKeepers(searchShapePage("1", "1", "2"))
	if len(kept) != 2 {
		t.Errorf("want 2 survivors (one duplicate dropped), got %d (%v)", len(kept), kept)
	}
	if plan.dropped != 1 {
		t.Errorf("plan.dropped = %d, want 1", plan.dropped)
	}
}

// A nil coalescer (coalescing disabled) keeps every row and commits safely.
func TestSelectKeepersNilCoalescerKeepsEverything(t *testing.T) {
	var c *paramShapeCoalescer // newParamShapeCoalescer(0) returns nil
	kept, plan := c.selectKeepers(searchShapePage("1", "2", "3"))
	if len(kept) != 3 {
		t.Errorf("nil coalescer must keep every record, got %d", len(kept))
	}
	c.commit(plan) // must not panic
}

// Path-segment normalization: per-record path ids share the pathshape template,
// so path-only records become coalescable; routes that only look varied (me,
// slugs, versions) keep their own shape.
func TestParamShapeRepresentative_PathShape(t *testing.T) {
	rep := func(method, rawURL string) (string, string, bool) {
		return paramShapeRepresentative(recordURLDesc{method: method, url: rawURL})
	}

	k1, v1, ok1 := rep("GET", "https://a.com/users/1")
	k2, v2, ok2 := rep("GET", "https://a.com/users/2")
	if !ok1 || !ok2 {
		t.Fatal("a path-only GET with a normalized segment must be coalescable")
	}
	if k1 != k2 {
		t.Errorf("/users/1 and /users/2 must share a shape key: %q vs %q", k1, k2)
	}
	if v1 == v2 {
		t.Error("the value signature must carry the concrete normalized segment")
	}
	if !strings.Contains(v1, "p:1=1") {
		t.Errorf("value signature %q should name the normalized segment as p:1=1", v1)
	}

	// /users/me is a literal route: no normalized segment, nothing to key on.
	kMe, _, okMe := rep("GET", "https://a.com/users/me")
	if okMe {
		t.Error("/users/me has no normalized segment and must not be coalescable")
	}
	if kMe == k1 {
		t.Error("/users/me must not share the /users/{int} shape")
	}
	for _, raw := range []string{"https://a.com/blog/my-post", "https://a.com/about-us", "https://a.com/api/v2/users"} {
		if _, _, ok := rep("GET", raw); ok {
			t.Errorf("%s has no normalized segment and must not be coalescable", raw)
		}
	}

	// UUID and hex segments normalize; distinct kinds are distinct shapes.
	kU1, _, okU1 := rep("GET", "https://a.com/orders/550e8400-e29b-41d4-a716-446655440000")
	kU2, _, okU2 := rep("GET", "https://a.com/orders/9b2f0c1e-1111-4222-8333-444455556666")
	kH, _, okH := rep("GET", "https://a.com/orders/e3b0c44298fc1c14")
	if !okU1 || !okU2 || !okH {
		t.Fatal("uuid and hex path segments must be coalescable")
	}
	if kU1 != kU2 {
		t.Error("two uuid orders must share a shape")
	}
	if kU1 == kH {
		t.Error("a uuid and a hex segment must not share a shape")
	}

	// Path normalization composes with query params: same names, different ids.
	kq1, _, _ := rep("GET", "https://a.com/users/1/posts?page=1")
	kq2, _, _ := rep("GET", "https://a.com/users/7/posts?page=3")
	if kq1 != kq2 {
		t.Error("query-bearing records on one path shape must share a key")
	}

	// The body-safety rule still wins over a normalized path.
	if _, _, ok := paramShapeRepresentative(recordURLDesc{method: "POST", url: "https://a.com/users/1"}); ok {
		t.Error("a POST with an unseen body must never be coalescable, even on a normalized path")
	}
	if _, _, ok := paramShapeRepresentative(recordURLDesc{method: "GET", url: "https://a.com/users/1", contentLength: 10}); ok {
		t.Error("a request with an unseen body must never be coalescable, even on a normalized path")
	}
}

func TestCoalesceUUIDsByParamShape_PathIDs(t *testing.T) {
	desc := map[string]recordURLDesc{
		"me":   {method: "GET", url: "https://a.com/users/me"},
		"blog": {method: "GET", url: "https://a.com/blog/my-post"},
		"post": {method: "POST", url: "https://a.com/users/99"},
	}
	uuids := []string{"me", "blog", "post"}
	for i := 1; i <= 50; i++ {
		id := fmt.Sprintf("u%d", i)
		desc[id] = recordURLDesc{method: "GET", url: fmt.Sprintf("https://a.com/users/%d", i)}
		uuids = append(uuids, id)
	}

	kept, dropped := coalesceUUIDsByParamShape(uuids, desc, 3)

	want := []string{"me", "blog", "post", "u1", "u2", "u3"}
	if !reflect.DeepEqual(kept, want) {
		t.Errorf("kept = %v, want %v", kept, want)
	}
	if dropped != 47 {
		t.Errorf("dropped = %d, want 47", dropped)
	}
}
