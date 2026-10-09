package jsext

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/internal/config"
	"go.uber.org/zap"
)

// LoadScripts discovers, reads, and validates .js and .ts extension files.
func LoadScripts(cfg *config.ExtensionsConfig) ([]*LoadedScript, error) {
	var scripts []*LoadedScript
	extractor := newMetadataExtractor()

	// Load from extension_dir
	if cfg.ExtensionDir != "" {
		dir := config.ExpandPath(cfg.ExtensionDir)
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			dirScripts, err := loadFromDir(dir, extractor)
			if err != nil {
				zap.L().Warn("Error loading scripts from directory",
					zap.String("dir", dir), zap.Error(err))
			}
			scripts = append(scripts, dirScripts...)
		}
	}

	// Load explicit script paths. CustomDir is shared with the YAML loader, so
	// YAML extensions and TypeScript declaration files are not ours to load:
	// feeding them to the JS VM only produced a spurious "Failed to load script".
	for _, scriptPath := range cfg.CustomDir {
		path := config.ExpandPath(scriptPath)
		if isNonScriptExtensionFile(path) {
			continue
		}
		script, err := loadScript(path, extractor)
		if err != nil {
			zap.L().Warn("Failed to load script",
				zap.String("path", path), zap.Error(err))
			continue
		}
		scripts = append(scripts, script)
	}

	return scripts, nil
}

func loadFromDir(dir string, extractor *metadataExtractor) ([]*LoadedScript, error) {
	var scripts []*LoadedScript

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if isNonScriptExtensionFile(name) {
			continue
		}
		if !strings.HasSuffix(name, ".js") && !strings.HasSuffix(name, ".ts") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		script, err := loadScript(path, extractor)
		if err != nil {
			zap.L().Warn("Failed to load script",
				zap.String("path", path), zap.Error(err))
			continue
		}
		scripts = append(scripts, script)
	}

	return scripts, nil
}

// isNonScriptExtensionFile reports whether a file that may sit next to (or be
// passed alongside) JS/TS extensions is not a script for this loader: YAML
// extensions belong to the yamlext package, and .d.ts files are type
// declarations (e.g. the vigolium.d.ts written by `ext preset`).
func isNonScriptExtensionFile(name string) bool {
	return strings.HasSuffix(name, ".vgm.yaml") ||
		strings.HasSuffix(name, ".vgm.yml") ||
		strings.HasSuffix(name, ".d.ts")
}

func loadScript(path string, extractor *metadataExtractor) (*LoadedScript, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read script %s: %w", path, err)
	}

	source := string(data)

	// Transpile TypeScript files to JavaScript
	if strings.HasSuffix(path, ".ts") {
		transpiled, transpileErr := TranspileTS(source, filepath.Base(path))
		if transpileErr != nil {
			return nil, transpileErr
		}
		source = transpiled
	}

	// Extract metadata using the shared VM
	metadata, err := extractor.Extract(source, path)
	if err != nil {
		return nil, fmt.Errorf("failed to extract metadata from %s: %w", path, err)
	}

	return &LoadedScript{
		Path:     path,
		Source:   source,
		Metadata: *metadata,
	}, nil
}

// metadataExtractor extracts script metadata by running each script in a FRESH
// Sobek VM. A previous version reused one VM across scripts and reset only
// module.exports, but top-level var/let/const/class/function declarations persist
// in the runtime's global scope — so a second script declaring the same
// identifier threw "already declared", making load order affect which scripts
// validated. A fresh VM per Extract eliminates that cross-script leakage.
type metadataExtractor struct{}

func newMetadataExtractor() *metadataExtractor {
	return &metadataExtractor{}
}

// newExtractorVM builds a fresh Sobek VM wired with stub vigolium.* APIs so a
// script can be evaluated far enough to read its module.exports metadata.
func newExtractorVM() *sobek.Runtime {
	vm := sobek.New()

	noopFn := func(call sobek.FunctionCall) sobek.Value { return sobek.Undefined() }

	vigolium := vm.NewObject()

	stubHTTP := vm.NewObject()
	_ = stubHTTP.Set("get", noopFn)
	_ = stubHTTP.Set("post", noopFn)
	_ = stubHTTP.Set("send", noopFn)
	_ = stubHTTP.Set("request", noopFn)
	_ = vigolium.Set("http", stubHTTP)

	stubLog := vm.NewObject()
	_ = stubLog.Set("info", noopFn)
	_ = stubLog.Set("warn", noopFn)
	_ = stubLog.Set("error", noopFn)
	_ = stubLog.Set("debug", noopFn)
	_ = vigolium.Set("log", stubLog)

	_ = vigolium.Set("config", vm.NewObject())

	stubUtils := vm.NewObject()
	for _, fn := range []string{
		"base64Encode", "base64Decode", "urlEncode", "urlDecode",
		"sha1", "sha256", "md5", "randomString",
		"htmlEncode", "htmlDecode", "sleep",
		"exec", "glob", "readFile", "readLines",
		"writeFile", "mkdir", "getEnv", "setEnv",
		"jsonExtract", "regexMatch", "regexExtract",
		"detectAnomaly", "extractParamNames",
	} {
		_ = stubUtils.Set(fn, noopFn)
	}
	// toSet returns an object (used at top-level in scripts), so it needs a real stub
	_ = stubUtils.Set("toSet", func(call sobek.FunctionCall) sobek.Value {
		return vm.NewObject()
	})
	_ = vigolium.Set("utils", stubUtils)

	stubScan := vm.NewObject()
	for _, fn := range []string{
		"listModules", "isInScope", "getScope", "setScope",
		"createFinding", "getCurrentScan",
	} {
		_ = stubScan.Set(fn, noopFn)
	}
	_ = vigolium.Set("scan", stubScan)

	_ = vm.Set("vigolium", vigolium)

	return vm
}

// Extract runs a script in a fresh VM and reads its module.exports metadata.
func (me *metadataExtractor) Extract(source, path string) (*ScriptMetadata, error) {
	vm := newExtractorVM()

	// Set up module.exports for the script
	exports := vm.NewObject()
	module := vm.NewObject()
	_ = module.Set("exports", exports)
	_ = vm.Set("module", module)
	_ = vm.Set("exports", exports)

	_, err := vm.RunString(source)
	if err != nil {
		return nil, fmt.Errorf("script execution error: %w", err)
	}

	// Read module.exports
	exportsVal := module.Get("exports")
	if exportsVal == nil || sobek.IsUndefined(exportsVal) || sobek.IsNull(exportsVal) {
		return nil, fmt.Errorf("script does not export module.exports")
	}

	obj := exportsVal.ToObject(vm)

	meta := &ScriptMetadata{}

	if v := obj.Get("id"); v != nil && !sobek.IsUndefined(v) {
		meta.ID = v.String()
	}
	if v := obj.Get("name"); v != nil && !sobek.IsUndefined(v) {
		meta.Name = v.String()
	}
	if v := obj.Get("severity"); v != nil && !sobek.IsUndefined(v) {
		meta.Severity = v.String()
	}
	if v := obj.Get("confidence"); v != nil && !sobek.IsUndefined(v) {
		meta.Confidence = v.String()
	}
	if v := obj.Get("type"); v != nil && !sobek.IsUndefined(v) {
		meta.Type = ScriptType(v.String())
	}
	if v := obj.Get("description"); v != nil && !sobek.IsUndefined(v) {
		meta.Description = v.String()
	}
	if v := obj.Get("scope"); v != nil && !sobek.IsUndefined(v) {
		meta.Scope = v.String()
	}
	if v := obj.Get("confirmationCriteria"); v != nil && !sobek.IsUndefined(v) && !sobek.IsNull(v) {
		meta.ConfirmationCriteria = stringOrLines(vm, v)
	}

	// Parse scanTypes array
	if v := obj.Get("scanTypes"); v != nil && !sobek.IsUndefined(v) {
		scanTypesObj := v.ToObject(vm)
		if scanTypesObj != nil {
			length := scanTypesObj.Get("length")
			if length != nil && !sobek.IsUndefined(length) {
				n := int(length.ToInteger())
				for i := 0; i < n; i++ {
					item := scanTypesObj.Get(fmt.Sprintf("%d", i))
					if item != nil && !sobek.IsUndefined(item) {
						meta.ScanTypes = append(meta.ScanTypes, item.String())
					}
				}
			}
		}
	}

	// Parse tags array
	if v := obj.Get("tags"); v != nil && !sobek.IsUndefined(v) {
		tagsObj := v.ToObject(vm)
		if tagsObj != nil {
			length := tagsObj.Get("length")
			if length != nil && !sobek.IsUndefined(length) {
				n := int(length.ToInteger())
				for i := 0; i < n; i++ {
					item := tagsObj.Get(fmt.Sprintf("%d", i))
					if item != nil && !sobek.IsUndefined(item) {
						meta.Tags = append(meta.Tags, strings.ToLower(item.String()))
					}
				}
			}
		}
	}

	// Validate required fields
	if meta.Type == "" {
		return nil, fmt.Errorf("script must export 'type' (active, passive, pre_hook, post_hook)")
	}
	if meta.ID == "" {
		base := filepath.Base(path)
		meta.ID = strings.TrimSuffix(base, ".js")
		meta.ID = strings.TrimSuffix(meta.ID, ".ts")
		meta.ID = strings.ReplaceAll(meta.ID, "_", "-")
	}
	if meta.Name == "" {
		meta.Name = meta.ID
	}

	return meta, nil
}

// stringOrLines reads a JS value that may be a string or an array of strings,
// joining array elements with newlines.
func stringOrLines(vm *sobek.Runtime, v sobek.Value) string {
	if _, isStr := v.Export().(string); isStr {
		return v.String()
	}
	obj := v.ToObject(vm)
	length := obj.Get("length")
	if length == nil || sobek.IsUndefined(length) {
		return v.String()
	}
	n := int(length.ToInteger())
	lines := make([]string, 0, n)
	for i := 0; i < n; i++ {
		item := obj.Get(fmt.Sprintf("%d", i))
		if item == nil || sobek.IsUndefined(item) || sobek.IsNull(item) {
			continue
		}
		lines = append(lines, item.String())
	}
	return strings.Join(lines, "\n")
}
