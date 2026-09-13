package spider

import (
	"context"
	"testing"
)

// TestCoordinatorExtractsHeadersFromBodylessResponses pins B14: header-derived
// URLs must survive a response with no body.
//
// The header extractor itself was always correct — its own unit tests passed.
// What was wrong was where the coordinator called it: after the `len(Body) < 10`
// early return, so it could not run on precisely the responses where a header is
// the only content there is. A 301 carrying Location, a 204 carrying
// Link rel=canonical, an empty 200 carrying Refresh or Content-Location all
// yielded zero discovered links through the coordinator.
//
// These cases go through extractInternal (not the individual extractor) on
// purpose: testing the extractor in isolation is what let the defect survive.
func TestCoordinatorExtractsHeadersFromBodylessResponses(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string][]string
		body    []byte
		wantURL string
	}{
		{
			name:    "301 with Location and no body",
			headers: map[string][]string{"Location": {"/admin/dashboard"}},
			body:    nil,
			wantURL: "https://example.com/admin/dashboard",
		},
		{
			name:    "empty body with Content-Location",
			headers: map[string][]string{"Content-Location": {"/asset"}},
			body:    []byte{},
			wantURL: "https://example.com/asset",
		},
		{
			name:    "204 with Link rel=canonical",
			headers: map[string][]string{"Link": {"</canonical-page>; rel=canonical"}},
			body:    nil,
			wantURL: "https://example.com/canonical-page",
		},
		{
			name:    "empty 200 with Refresh",
			headers: map[string][]string{"Refresh": {"0; url=/next-step"}},
			body:    nil,
			wantURL: "https://example.com/next-step",
		},
		{
			// A body under the 10-byte HTML threshold is still a short body: the
			// header must be read even though the body is too small to parse.
			name:    "sub-threshold body still yields the header URL",
			headers: map[string][]string{"Location": {"/short"}},
			body:    []byte("ok"),
			wantURL: "https://example.com/short",
		},
	}

	coordinator := createTestCoordinator()
	baseURL := mustParseURL("https://example.com/")

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := &HTTPResponse{
				URL:     baseURL,
				Headers: tc.headers,
				Body:    tc.body,
			}

			result, err := coordinator.extractInternal(context.Background(), baseURL, response)
			if err != nil {
				t.Fatalf("extractInternal: %v", err)
			}
			if result == nil {
				t.Fatal("extractInternal returned nil result")
			}

			var found bool
			for _, u := range result.Links {
				if u != nil && u.String() == tc.wantURL {
					found = true
					break
				}
			}
			if !found {
				got := make([]string, 0, len(result.Links))
				for _, u := range result.Links {
					if u != nil {
						got = append(got, u.String())
					}
				}
				t.Errorf("header URL %q not discovered; got %v", tc.wantURL, got)
			}
		})
	}
}

// TestCoordinatorKeepsHTMLWorkGatedOnABody guards the other half of the change:
// moving the header extractor above the size check must not drag the HTML
// extractors up with it. A bodyless response has nothing to parse, and running
// the DOM extractors over it would be wasted work on the hottest path in
// discovery.
func TestCoordinatorKeepsHTMLWorkGatedOnABody(t *testing.T) {
	coordinator := createTestCoordinator()
	baseURL := mustParseURL("https://example.com/")

	response := &HTTPResponse{
		URL:     baseURL,
		Headers: map[string][]string{"Location": {"/only-header"}},
		Body:    nil,
	}

	result, err := coordinator.extractInternal(context.Background(), baseURL, response)
	if err != nil {
		t.Fatalf("extractInternal: %v", err)
	}

	// The short-body path returns before form extraction, so FormRequests must
	// stay empty — that is the marker that the early return is still in place.
	if len(result.FormRequests) != 0 {
		t.Errorf("bodyless response produced %d form requests; the short-body return "+
			"should still skip HTML/form work", len(result.FormRequests))
	}
	if response.HTML != nil {
		t.Error("bodyless response was HTML-parsed; the size gate should still skip parsing")
	}
}
