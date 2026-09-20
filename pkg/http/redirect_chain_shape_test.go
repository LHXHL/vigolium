package http

import (
	"fmt"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// hopAt builds a minimal request/response pair standing in for one chain hop.
func hopAt(t *testing.T, url string) *httpmsg.HttpRequestResponse {
	t.Helper()
	rr, err := httpmsg.GetRawRequestFromURL(url)
	if err != nil {
		t.Fatalf("build hop %q: %v", url, err)
	}
	return rr
}

func shapedURLs(rows []ChainRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.RR.Target())
	}
	return out
}

func TestShapeRedirectChainCollapsesCanonicalHops(t *testing.T) {
	tests := []struct {
		name  string
		hops  []string
		final string
		want  []string
	}{
		{
			// The `curl -L ctdtoolkit.netflix.net` shape: the only hop is a
			// scheme upgrade, so the chain is one record at the canonical URL.
			name:  "scheme upgrade collapses to nothing",
			hops:  []string{"http://app.example.test/"},
			final: "https://app.example.test/",
			want:  nil,
		},
		{
			name:  "trailing slash collapses",
			hops:  []string{"http://app.example.test/dir"},
			final: "http://app.example.test/dir/",
			want:  nil,
		},
		{
			name:  "apex to www collapses",
			hops:  []string{"http://example.test/"},
			final: "https://www.example.test/",
			want:  nil,
		},
		{
			name:  "a real relocation is kept",
			hops:  []string{"http://app.example.test/old"},
			final: "http://app.example.test/new",
			want:  []string{"http://app.example.test/old"},
		},
		{
			// Only the spelling hops go; the relocation between them stays.
			name:  "mixed chain keeps only what moved",
			hops:  []string{"http://example.test/old", "https://www.example.test/old"},
			final: "https://www.example.test/new",
			want:  []string{"https://www.example.test/old"},
		},
		{
			name:  "a port change is not canonical",
			hops:  []string{"http://example.test:18092/"},
			final: "https://example.test:18443/",
			want:  []string{"http://example.test:18092/"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hops := make([]*httpmsg.HttpRequestResponse, 0, len(tt.hops))
			for _, u := range tt.hops {
				hops = append(hops, hopAt(t, u))
			}
			got := shapedURLs(ShapeRedirectChain(hops, tt.final))
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("row %d = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// TestShapeRedirectChainCapKeepsTheEnds is the 12-hop case: ten contentless
// rows per work item, none of which carried the destination. The cap keeps the
// hop the submitted target answered and the ones nearest the destination, and
// marks the row the gap follows.
func TestShapeRedirectChainCapKeepsTheEnds(t *testing.T) {
	var hops []*httpmsg.HttpRequestResponse
	for i := range 9 {
		hops = append(hops, hopAt(t, fmt.Sprintf("http://example.test/h/%d", i)))
	}
	rows := ShapeRedirectChain(hops, "http://example.test/h/9")

	if len(rows) != maxStoredChainRows-1 {
		t.Fatalf("stored %d intermediates, want %d (the terminal row takes the fourth)",
			len(rows), maxStoredChainRows-1)
	}
	got := shapedURLs(rows)
	want := []string{"http://example.test/h/0", "http://example.test/h/7", "http://example.test/h/8"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d = %q, want %q", i, got[i], want[i])
		}
	}
	if !rows[0].Truncated {
		t.Error("the row the gap follows must be marked truncated; a consumer otherwise reads /h/0 -> /h/7 as a real hop")
	}
	for i := 1; i < len(rows); i++ {
		if rows[i].Truncated {
			t.Errorf("row %d is contiguous with the next and must not be marked truncated", i)
		}
	}
}

// TestShapeRedirectChainShortChainsUnchanged pins that the cap does not touch
// the chains people actually have: google.com settles in three, github.com in
// two.
func TestShapeRedirectChainShortChainsUnchanged(t *testing.T) {
	hops := []*httpmsg.HttpRequestResponse{
		hopAt(t, "http://a.example.test/one"),
		hopAt(t, "http://a.example.test/two"),
	}
	rows := ShapeRedirectChain(hops, "http://a.example.test/three")
	if len(rows) != 2 {
		t.Fatalf("stored %d rows, want 2", len(rows))
	}
	for i, r := range rows {
		if r.Truncated {
			t.Errorf("row %d marked truncated on a chain that was never cut", i)
		}
	}
}
