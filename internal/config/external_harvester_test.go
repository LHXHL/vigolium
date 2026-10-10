package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vigolium/vigolium/pkg/harvester"
)

func TestExternalHarvesterConfig_ShapingDefaults(t *testing.T) {
	d := DefaultExternalHarvesterConfig()
	if d.PerShape != harvester.DefaultPerShape || d.MaxURLs != harvester.DefaultMaxURLs ||
		d.CDX.PageSize != harvester.DefaultCDXPageSize || d.CDX.MaxRows != harvester.DefaultCDXMaxRows {
		t.Fatalf("defaults = %+v", d)
	}
}

func TestExternalHarvesterConfig_ShapingFromYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	yaml := "external_harvester:\n  per_shape: 7\n  cdx:\n    max_rows: -1\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := LoadSettings(path)
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	eh := s.ExternalHarvester
	if eh.PerShape != 7 || eh.CDX.MaxRows != -1 {
		t.Errorf("explicit values not applied: %+v", eh)
	}
	// Keys the file leaves out keep their defaults rather than zeroing.
	if eh.MaxURLs != harvester.DefaultMaxURLs || eh.CDX.PageSize != harvester.DefaultCDXPageSize {
		t.Errorf("omitted keys lost their defaults: %+v", eh)
	}
}

func TestExternalHarvesterConfig_ValidatePageSize(t *testing.T) {
	cfg := DefaultExternalHarvesterConfig()
	cfg.CDX.PageSize = -5
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for negative cdx.page_size")
	}
}
