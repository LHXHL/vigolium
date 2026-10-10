package sourcemap_ingest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// A real-world map that bundles node_modules names thousands of sources. The
// parser used to reject any map over 512 sources, so this module reported
// nothing at all for exactly the maps that disclose the most.
func TestScanPerRequest_LargeMapIsReportedAsTruncated(t *testing.T) {
	t.Parallel()
	sources := []string{"webpack:///./src/api/client.ts"}
	contents := []string{"export const load = () => fetch(\"/api/v1/orders\");"}
	for i := range 1500 {
		sources = append(sources, fmt.Sprintf("webpack:///./node_modules/pkg%04d/index.js", i))
		contents = append(contents, fmt.Sprintf("module.exports = %d;", i))
	}
	encoded, err := json.Marshal(map[string]any{
		"version": 3, "sources": sources, "sourcesContent": contents, "mappings": "AAAA",
	})
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".map") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(encoded)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/static/js/main.abc.js"),
		"text/javascript",
		"(()=>{})();\n//# sourceMappingURL=main.abc.js.map\n",
	)
	feeder := &recordingFeeder{}
	results, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{RequestFeeder: feeder})
	require.NoError(t, err)
	require.Len(t, results, 1, "a truncated map is still an exposure")

	meta := results[0].Metadata
	assert.Equal(t, severity.Medium, results[0].Info.Severity)
	assert.Equal(t, true, meta["truncated"])
	assert.Equal(t, 1501, meta["sources_total"])
	assert.Equal(t, 512, meta["sources_recovered"])
	assert.Contains(t, results[0].Info.Description, "1501 sources")
	assert.Contains(t, feeder.urls(), srv.URL+"/api/v1/orders",
		"the application source is admitted ahead of vendor code and mined for routes")
}
