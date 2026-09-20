package runner

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigolium/vigolium/pkg/database"
)

// TestSourceMapArtifactOrigin covers both shapes the jsonb metadata column comes
// back in. SQLite round-trips the Go string through JSON encoding, so the object
// arrives quoted; PostgreSQL returns it natively. Getting this wrong is silent —
// the finding still saves, just with no URL or host attached.
func TestSourceMapArtifactOrigin(t *testing.T) {
	inner, err := json.Marshal(map[string]string{
		"generated_url": "https://app.example.test/static/js/main.abc.js",
		"virtual_url":   "https://app.example.test/static/js/main.abc.js#source=src%2FApp.tsx",
		"source_path":   "src/App.tsx",
		"language":      "tsx",
	})
	assert.NoError(t, err)
	doubleEncoded, err := json.Marshal(string(inner))
	assert.NoError(t, err)

	tests := []struct {
		name     string
		metadata string
		filename string
		wantURL  string
		wantPath string
	}{
		{
			name:     "native jsonb object",
			metadata: string(inner),
			filename: "src/App.tsx",
			wantURL:  "https://app.example.test/static/js/main.abc.js",
			wantPath: "src/App.tsx",
		},
		{
			name:     "sqlite double-encoded string",
			metadata: string(doubleEncoded),
			filename: "src/App.tsx",
			wantURL:  "https://app.example.test/static/js/main.abc.js",
			wantPath: "src/App.tsx",
		},
		{
			name:     "missing metadata falls back to filename",
			metadata: "",
			filename: "src/Fallback.tsx",
			wantURL:  "",
			wantPath: "src/Fallback.tsx",
		},
		{
			name:     "unparseable metadata falls back to filename",
			metadata: "not json at all",
			filename: "src/Fallback.tsx",
			wantURL:  "",
			wantPath: "src/Fallback.tsx",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotURL, gotPath := sourceMapArtifactOrigin(&database.AnalysisArtifact{
				Metadata: tt.metadata,
				Filename: tt.filename,
			})
			assert.Equal(t, tt.wantURL, gotURL)
			assert.Equal(t, tt.wantPath, gotPath)
		})
	}
}
