package knownissuescan

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestTemplateSources(t *testing.T) {
	dir := t.TempDir()
	rel := filepath.Join("http", "cves", "x.yaml")
	if err := os.MkdirAll(filepath.Join(dir, "http", "cves"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, rel), []byte("id: x"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := templateSources("", nil); got != nil {
		t.Errorf("nothing configured → %v, want nuclei's default (nil)", got)
	}
	if got := templateSources(dir, nil); !reflect.DeepEqual(got, []string{dir}) {
		t.Errorf("dir only → %v", got)
	}
	// Explicit templates are the only sources; a relative one that exists
	// under the templates dir is anchored there, an unknown one passes through
	// for nuclei to resolve.
	got := templateSources(dir, []string{rel, "unknown/y.yaml", "/abs/z.yaml"})
	want := []string{filepath.Join(dir, rel), "unknown/y.yaml", "/abs/z.yaml"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("explicit → %v, want %v", got, want)
	}
}
