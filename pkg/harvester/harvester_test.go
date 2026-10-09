package harvester

import (
	"context"
	"slices"
	"strconv"
	"testing"
	"time"
)

// fakeSource replays fixed results per domain.
type fakeSource struct {
	name    string
	results map[string][]Result

	pageSize, maxRows int // recorded by setCDXBounds
}

func (f *fakeSource) Name() string   { return f.name }
func (f *fakeSource) NeedsKey() bool { return false }
func (f *fakeSource) Run(_ context.Context, domain string) <-chan Result {
	ch := make(chan Result, len(f.results[domain]))
	for _, r := range f.results[domain] {
		ch <- r
	}
	close(ch)
	return ch
}
func (f *fakeSource) setCDXBounds(pageSize, maxRows int) { f.pageSize, f.maxRows = pageSize, maxRows }

func TestHarvest_ShapesAndReportsStats(t *testing.T) {
	var a []Result
	for i := range 10 {
		a = append(a, Result{Source: "fake", URL: "https://a.example/item/" + strconv.Itoa(i) + "?utm_source=x"})
	}
	a = append(a,
		Result{Source: "fake", URL: "https://a.example/logo.png"},
		Result{Source: "fake", URL: "https://A.example:443/item/0"}, // duplicate of the first
		Result{Source: "fake", Limit: LimitCDXMaxRows},
	)
	src := &fakeSource{name: "fake", results: map[string][]Result{
		"a.example": a,
		"b.example": {{Source: "fake", URL: "https://b.example/item/1"}},
	}}

	h := New([]Source{src}, time.Minute).WithOptions(Options{PerShape: 2, CDXPageSize: 50, CDXMaxRows: 500})
	if src.pageSize != 50 || src.maxRows != 500 {
		t.Errorf("CDX bounds not handed to the source: page=%d max=%d", src.pageSize, src.maxRows)
	}

	var got []string
	for u := range h.Harvest(context.Background(), []string{"a.example", "b.example"}) {
		got = append(got, u)
	}
	slices.Sort(got)
	want := []string{"https://a.example/item/0", "https://a.example/item/1", "https://b.example/item/1"}
	if !slices.Equal(got, want) {
		t.Errorf("emitted %v, want %v", got, want)
	}

	st := h.Stats()
	if st.Raw != 13 || st.Kept != 3 || st.OverShape != 8 || st.Static != 1 || st.Duplicate != 1 {
		t.Errorf("stats = %+v", st)
	}
	if !slices.Equal(st.Limits, []string{LimitCDXMaxRows}) {
		t.Errorf("limits = %v, want [%s]", st.Limits, LimitCDXMaxRows)
	}
}

func TestHarvest_DefaultBounds(t *testing.T) {
	src := &fakeSource{name: "fake"}
	New([]Source{src}, time.Minute)
	if src.pageSize != DefaultCDXPageSize || src.maxRows != DefaultCDXMaxRows {
		t.Errorf("defaults not applied: page=%d max=%d", src.pageSize, src.maxRows)
	}
}
