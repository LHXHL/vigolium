package yamlext

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
	"go.uber.org/zap"
)

const yamlExtSuffix = ".vgm.yaml"

// yamlExtSuffixes lists every accepted YAML extension suffix. The JS loader
// skips the same set, so a file never falls between the two loaders.
var yamlExtSuffixes = []string{yamlExtSuffix, ".vgm.yml"}

// IsYAMLExtension returns true if the filename has the .vgm.yaml (or .vgm.yml)
// extension.
func IsYAMLExtension(name string) bool {
	for _, suffix := range yamlExtSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

// trimYAMLExtSuffix strips the YAML extension suffix from a file name.
func trimYAMLExtSuffix(name string) string {
	for _, suffix := range yamlExtSuffixes {
		if strings.HasSuffix(name, suffix) {
			return strings.TrimSuffix(name, suffix)
		}
	}
	return name
}

// Load stages a YAML extension can fail at (the jsext loader shares the names).
const (
	StageRead        = "read"
	StageSchema      = "schema"
	StageUnknownType = "unknown_type"
)

// LoadFailure is one .vgm.yaml file that did not load. Explicit says it was
// named directly (--ext, extensions.custom_dir) rather than found in the
// extension directory.
type LoadFailure struct {
	Path     string
	Stage    string
	Err      error
	Explicit bool
}

// LoadExtension parses and validates a single .vgm.yaml file. Unknown keys
// are logged as warnings; LoadExtensionStrict makes them an error.
func LoadExtension(path string) (*ExtensionDef, error) {
	def, _, err := loadExtension(path, false)
	return def, err
}

// LoadExtensionStrict is LoadExtension with unknown keys as a load error.
func LoadExtensionStrict(path string) (*ExtensionDef, error) {
	def, _, err := loadExtension(path, true)
	return def, err
}

// loadExtension parses one file and reports the stage of any failure.
func loadExtension(path string, strict bool) (*ExtensionDef, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, StageRead, fmt.Errorf("failed to read YAML extension %s: %w", path, err)
	}

	root, err := parseDocument(data)
	if err != nil {
		return nil, StageSchema, fmt.Errorf("failed to parse YAML extension %s: %w", path, err)
	}
	if issues, _ := checkSchema(root); len(issues) > 0 {
		if strict {
			first := issues[0]
			more := ""
			if len(issues) > 1 {
				more = fmt.Sprintf(" (and %d more)", len(issues)-1)
			}
			return nil, StageSchema, fmt.Errorf("YAML extension %s:%d: %s%s", path, first.Line, first.Message(), more)
		}
		for _, is := range issues {
			zap.L().Warn("YAML extension has an unknown key; it is ignored (extensions.yaml_strict: true makes this a load failure)",
				zap.String("path", path), zap.Int("line", is.Line), zap.String("issue", is.Message()))
		}
	}

	var def ExtensionDef
	if root != nil {
		if err := root.Decode(&def); err != nil {
			return nil, StageSchema, fmt.Errorf("failed to parse YAML extension %s: %w", path, err)
		}
	}

	def.sourcePath = path

	// Apply defaults
	if def.MatchersCondition == "" {
		def.MatchersCondition = "or"
	}
	if def.ID == "" {
		base := filepath.Base(path)
		def.ID = trimYAMLExtSuffix(base)
		def.ID = strings.ReplaceAll(def.ID, "_", "-")
	}
	if def.Name == "" {
		def.Name = def.ID
	}

	// Validate required fields
	if def.Type == "" {
		return nil, StageSchema, fmt.Errorf("YAML extension %s: missing required field 'type'", path)
	}

	switch def.Type {
	case "active", "passive", "pre_hook", "post_hook":
		// valid
	default:
		return nil, StageUnknownType, fmt.Errorf("YAML extension %s: invalid type %q (must be active, passive, pre_hook, or post_hook)", path, def.Type)
	}

	return &def, "", nil
}

// LoadFromConfig discovers and loads all .vgm.yaml files from the extensions
// config. Files that fail are logged and skipped; LoadFromConfigReport returns
// them as well.
func LoadFromConfig(cfg *config.ExtensionsConfig) ([]*ExtensionDef, error) {
	defs, _ := LoadFromConfigReport(cfg)
	return defs, nil
}

// LoadFromConfigReport is LoadFromConfig plus every file that failed to load.
// cfg.YAMLStrict makes an unknown key a failure rather than a warning.
func LoadFromConfigReport(cfg *config.ExtensionsConfig) ([]*ExtensionDef, []LoadFailure) {
	var defs []*ExtensionDef
	var failures []LoadFailure

	// Load from extension_dir
	if cfg.ExtensionDir != "" {
		dir := config.ExpandPath(cfg.ExtensionDir)
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			dirDefs, dirFailures, err := loadFromDir(dir, cfg.YAMLStrict)
			if err != nil {
				zap.L().Warn("Error loading YAML extensions from directory",
					zap.String("dir", dir), zap.Error(err))
			}
			defs = append(defs, dirDefs...)
			failures = append(failures, dirFailures...)
		}
	}

	// Load explicit script paths (only .vgm.yaml/.vgm.yml ones)
	for _, scriptPath := range cfg.CustomDir {
		path := config.ExpandPath(scriptPath)
		if !IsYAMLExtension(path) {
			continue
		}
		def, stage, err := loadExtension(path, cfg.YAMLStrict)
		if err != nil {
			zap.L().Warn("Failed to load YAML extension",
				zap.String("path", path), zap.Error(err))
			failures = append(failures, LoadFailure{Path: path, Stage: stage, Err: err, Explicit: true})
			continue
		}
		def.explicit = true
		defs = append(defs, def)
	}

	return defs, failures
}

func loadFromDir(dir string, strict bool) ([]*ExtensionDef, []LoadFailure, error) {
	var defs []*ExtensionDef
	var failures []LoadFailure

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !IsYAMLExtension(entry.Name()) {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		def, stage, err := loadExtension(path, strict)
		if err != nil {
			zap.L().Warn("Failed to load YAML extension",
				zap.String("path", path), zap.Error(err))
			failures = append(failures, LoadFailure{Path: path, Stage: stage, Err: err})
			continue
		}
		defs = append(defs, def)
	}

	return defs, failures, nil
}
