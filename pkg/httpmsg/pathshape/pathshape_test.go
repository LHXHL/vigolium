package pathshape

import (
	"reflect"
	"testing"
)

func TestKind(t *testing.T) {
	tests := []struct {
		seg  string
		want SegKind
	}{
		// Integers, including the "0"/"1" that mutation.Classify can call Boolean.
		{"0", Int},
		{"1", Int},
		{"2", Int},
		{"42", Int},
		{"4532015112830366", Int}, // Luhn-valid: a credit card to Classify
		{"5551234567", Int},       // phone-shaped digits
		// Versions are always literal.
		{"v1", Literal},
		{"v2", Literal},
		{"V10", Literal},
		// UUID and hex.
		{"550e8400-e29b-41d4-a716-446655440000", UUID},
		{"550E8400-E29B-41D4-A716-446655440000", UUID},
		{"e3b0c442", Hex},
		{"E3B0C442", Hex}, // upper-case would otherwise read as base64
		{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Hex},
		{"abcdef1", Literal}, // 7 chars: too short
		// Dates and timestamps.
		{"2024-01-02", Date},
		{"2024-01-02T10:30:00Z", TS},
		// Email, JWT, base64.
		{"user@example.com", Email},
		{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl", JWT},
		{"eyJhbGciOiJIUzI1NiJ9", B64},
		{"QWxhZGRpbjpvcGVuIHNlc2FtZQ==", B64},
		{"QWxhZGRpbg==", Literal}, // base64 but under 16 chars
		// Never collapsed: words, slugs, enums, unknowns, structured codes.
		{"me", Literal},
		{"about-us", Literal},
		{"my-post", Literal},
		{"admin", Literal},
		{"active", Literal},
		{"true", Literal},
		{"ORD-00042", Literal},
		{"3.14", Literal},
		{"index.html", Literal},
		{"", Literal},
	}
	for _, tt := range tests {
		if got := Kind(tt.seg); got != tt.want {
			t.Errorf("Kind(%q) = %q, want %q", tt.seg, got, tt.want)
		}
	}
}

func TestShape(t *testing.T) {
	tests := []struct {
		path      string
		want      string
		wantKinds []SegKind
	}{
		{"", "", nil},
		{"/", "/", nil},
		{"/users/0", "/users/{int}", []SegKind{Literal, Int}},
		{"/users/1", "/users/{int}", []SegKind{Literal, Int}},
		{"/users/me", "/users/me", []SegKind{Literal, Literal}},
		{"/about-us", "/about-us", []SegKind{Literal}},
		{"/blog/my-post", "/blog/my-post", []SegKind{Literal, Literal}},
		{"/api/v2/users", "/api/v2/users", []SegKind{Literal, Literal, Literal}},
		{"/archive/2024-01-02", "/archive/{date}", []SegKind{Literal, Date}},
		{"/blobs/e3b0c442", "/blobs/{hex}", []SegKind{Literal, Hex}},
		{
			"/users/42/orders/550e8400-e29b-41d4-a716-446655440000",
			"/users/{int}/orders/{uuid}",
			[]SegKind{Literal, Int, Literal, UUID},
		},
		{"/api/v2/orders/123/", "/api/v2/orders/{int}/", []SegKind{Literal, Literal, Literal, Int}},
		{"users//7", "users//{int}", []SegKind{Literal, Int}},
	}
	for _, tt := range tests {
		got, kinds := Shape(tt.path)
		if got != tt.want {
			t.Errorf("Shape(%q) template = %q, want %q", tt.path, got, tt.want)
		}
		if !reflect.DeepEqual(kinds, tt.wantKinds) {
			t.Errorf("Shape(%q) kinds = %v, want %v", tt.path, kinds, tt.wantKinds)
		}
	}
}

func TestShapeCollapsesRecordsNotRoutes(t *testing.T) {
	a, _ := Shape("/users/1")
	b, _ := Shape("/users/9999")
	if a != b {
		t.Errorf("per-record paths should share a shape: %q vs %q", a, b)
	}
	me, _ := Shape("/users/me")
	if me == a {
		t.Error("/users/me must not share a shape with /users/{int}")
	}
	v1, _ := Shape("/api/v1/x")
	v2, _ := Shape("/api/v2/x")
	if v1 == v2 {
		t.Error("API versions must stay distinct")
	}
}

func TestSegmentsAlignWithKinds(t *testing.T) {
	path := "//a/42//b/"
	segs := Segments(path)
	_, kinds := Shape(path)
	if !reflect.DeepEqual(segs, []string{"a", "42", "b"}) {
		t.Fatalf("Segments = %v", segs)
	}
	if len(kinds) != len(segs) || kinds[1] != Int {
		t.Fatalf("kinds %v not aligned with segments %v", kinds, segs)
	}
}
