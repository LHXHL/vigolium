package modkit

import (
	"sync"
	"testing"
)

func TestTechRegistry_NilSafe(t *testing.T) {
	var r *TechRegistry
	r.Mark("example.com", "nextjs") // must not panic
	if r.Has("example.com", "nextjs") {
		t.Fatal("nil registry should not report any tech")
	}
	if r.HasAny("example.com", []string{"nextjs"}) {
		t.Fatal("nil registry should not report any tech")
	}
	if r.HostKnown("example.com") {
		t.Fatal("nil registry should report no known hosts")
	}
}

func TestTechRegistry_MarkAndQuery(t *testing.T) {
	r := NewTechRegistry()
	r.Mark("Example.com", " NextJS ")
	r.Mark("example.com", "nodejs")

	if !r.Has("example.com", "nextjs") {
		t.Fatal("expected normalized tag lookup to succeed")
	}
	if !r.HostKnown("EXAMPLE.com") {
		t.Fatal("expected HostKnown to be case-insensitive")
	}
	if !r.HasAny("example.com", []string{"php", "nextjs"}) {
		t.Fatal("HasAny should match one of the candidates")
	}
	if r.HasAny("example.com", []string{"php", "spring"}) {
		t.Fatal("HasAny should return false when no candidate matches")
	}
	if r.Has("other.com", "nextjs") {
		t.Fatal("unknown host should not report any tech")
	}
}

func TestTechRegistry_EmptyInputsAreNoOp(t *testing.T) {
	r := NewTechRegistry()
	r.Mark("", "nextjs")
	r.Mark("example.com", "")
	if r.HostKnown("example.com") {
		t.Fatal("empty inputs must not register a host")
	}
}

func TestTechRegistry_ConcurrentWrites(t *testing.T) {
	r := NewTechRegistry()
	var wg sync.WaitGroup
	tags := []string{"nextjs", "nodejs", "javascript", "react"}
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			r.Mark("example.com", tags[idx%len(tags)])
		}(i)
	}
	wg.Wait()
	for _, tag := range tags {
		if !r.Has("example.com", tag) {
			t.Fatalf("expected %q to be marked under concurrent writes", tag)
		}
	}
}

func TestTechRegistry_Tags(t *testing.T) {
	r := NewTechRegistry()
	r.Mark("example.com", "nginx")
	r.Mark("example.com", "Django")
	r.Mark("other.example", "spring")

	got := r.Tags("example.com")
	want := []string{"django", "nginx"}
	if len(got) != len(want) {
		t.Fatalf("Tags() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Tags() = %v, want %v (sorted, so two identical scans do not diff)", got, want)
		}
	}

	if got := r.Tags("unknown.example"); got != nil {
		t.Errorf("Tags(unknown) = %v, want nil", got)
	}
	if got := r.Tags(""); got != nil {
		t.Errorf("Tags(\"\") = %v, want nil", got)
	}
	var nilReg *TechRegistry
	if got := nilReg.Tags("example.com"); got != nil {
		t.Errorf("nil registry Tags() = %v, want nil", got)
	}
}

// TestTechRegistry_TagsIsACopy verifies a caller cannot reach into the
// registry's own set through the returned slice and corrupt another module's
// gating data.
func TestTechRegistry_TagsIsACopy(t *testing.T) {
	r := NewTechRegistry()
	r.Mark("example.com", "nginx")

	tags := r.Tags("example.com")
	tags[0] = "mutated"

	if !r.Has("example.com", "nginx") {
		t.Fatal("mutating the returned slice changed the registry")
	}
}
