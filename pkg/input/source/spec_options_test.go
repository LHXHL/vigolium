package source

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A Postman collection gets the -t target as {{baseUrl}} and --spec-var
// values for its {{variables}}, through the same ApplySpecOptions scan, the
// runner and ingest use for OpenAPI and WSDL.
func TestApplySpecOptionsPostman(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api.postman.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"info":{"_postman_id":"x","name":"t",
"schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
"item":[{"name":"user","request":{"method":"GET","url":{"raw":"{{baseUrl}}/users/{{userId}}"}}}]}`), 0o600))

	src, err := NewInputSource(SourceConfig{FilePath: path, Format: "postman", BufferSize: 4})
	require.NoError(t, err)
	t.Cleanup(func() { _ = src.Close() })
	ApplySpecOptions(src, SpecOptions{
		BaseURL:   "http://127.0.0.1:8080",
		Variables: map[string]string{"userId": "42"},
	})

	item, err := src.Next(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:8080/users/42", item.Request.Target())
	_, err = src.Next(context.Background())
	assert.True(t, IsEOF(err))
}

// A non-spec source is left alone.
func TestApplySpecOptionsIgnoresOtherFormats(t *testing.T) {
	src := NewTargetSource([]string{"http://127.0.0.1:1/"}, nil)
	ApplySpecOptions(src, SpecOptions{BaseURL: "http://other.test"})
}
