package jsext

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/internal/config"
	"go.uber.org/zap"
)

// LoadStage names the step at which an extension failed to load.
type LoadStage string

const (
	LoadStageRead        LoadStage = "read"         // the file could not be read
	LoadStageTranspile   LoadStage = "transpile"    // TypeScript did not transpile
	LoadStageCompile     LoadStage = "compile"      // the JavaScript does not parse
	LoadStageMetadata    LoadStage = "metadata"     // top-level code threw, or module.exports is unusable
	LoadStageSchema      LoadStage = "schema"       // a YAML extension does not match the schema
	LoadStageUnknownType LoadStage = "unknown_type" // the declared type is not active/passive/pre_hook/post_hook
	LoadStageModule      LoadStage = "module"       // the module or hook could not be built
)

// LoadFailure is one extension that did not load. Explicit says the file was
// named directly (--ext, extensions.custom_dir) rather than found in the
// extension directory: a scan aborts on an explicit failure, and only reports a
// directory one.
type LoadFailure struct {
	Path     string
	ID       string // module id ("ext-…") when the metadata got that far
	Stage    LoadStage
	Err      error
	Explicit bool
}

func (f LoadFailure) Error() string {
	name := f.Path
	if name == "" {
		name = f.ID
	}
	return fmt.Sprintf("extension %s failed to load (%s): %v", name, f.Stage, f.Err)
}

func (f LoadFailure) Unwrap() error { return f.Err }

// LoadScripts discovers, reads, and validates .js and .ts extension files.
// Files that fail to load are logged and skipped; LoadScriptsReport returns
// them as well.
func LoadScripts(cfg *config.ExtensionsConfig) ([]*LoadedScript, error) {
	scripts, _ := LoadScriptsReport(cfg)
	return scripts, nil
}

// LoadScriptsReport is LoadScripts plus every file that failed to load.
func LoadScriptsReport(cfg *config.ExtensionsConfig) ([]*LoadedScript, []LoadFailure) {
	var scripts []*LoadedScript
	var failures []LoadFailure
	extractor := newMetadataExtractor()
	extractor.vars = cfg.Variables

	// Load from extension_dir
	if cfg.ExtensionDir != "" {
		dir := config.ExpandPath(cfg.ExtensionDir)
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			dirScripts, dirFailures, err := loadFromDir(dir, extractor)
			if err != nil {
				zap.L().Warn("Error loading scripts from directory",
					zap.String("dir", dir), zap.Error(err))
			}
			scripts = append(scripts, dirScripts...)
			failures = append(failures, dirFailures...)
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
		script, failure := loadScript(path, extractor)
		if failure != nil {
			failure.Explicit = true
			zap.L().Warn("Failed to load script",
				zap.String("path", path), zap.String("stage", string(failure.Stage)), zap.Error(failure.Err))
			failures = append(failures, *failure)
			continue
		}
		script.Explicit = true
		scripts = append(scripts, script)
	}

	return scripts, failures
}

func loadFromDir(dir string, extractor *metadataExtractor) ([]*LoadedScript, []LoadFailure, error) {
	var scripts []*LoadedScript
	var failures []LoadFailure

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
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
		script, failure := loadScript(path, extractor)
		if failure != nil {
			zap.L().Warn("Failed to load script",
				zap.String("path", path), zap.String("stage", string(failure.Stage)), zap.Error(failure.Err))
			failures = append(failures, *failure)
			continue
		}
		scripts = append(scripts, script)
	}

	return scripts, failures, nil
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

func loadScript(path string, extractor *metadataExtractor) (*LoadedScript, *LoadFailure) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &LoadFailure{Path: path, Stage: LoadStageRead, Err: err}
	}

	source := string(data)

	// Transpile TypeScript files to JavaScript
	if strings.HasSuffix(path, ".ts") {
		transpiled, transpileErr := TranspileTS(source, filepath.Base(path))
		if transpileErr != nil {
			return nil, &LoadFailure{Path: path, Stage: LoadStageTranspile, Err: transpileErr}
		}
		source = transpiled
	}

	// Extract metadata by running the top-level code in a load-mode VM.
	res, err := extractor.extract(source, path)
	if err != nil {
		f := &LoadFailure{Path: path, Stage: LoadStageMetadata, Err: err}
		var le *loadStageError
		if errors.As(err, &le) {
			f.Stage, f.Err = le.stage, le.err
		}
		return nil, f
	}
	for _, c := range res.TopLevelEffects {
		zap.L().Debug("Extension calls an effectful API at load time; it was stubbed",
			zap.String("path", path), zap.String("api", c.API), zap.Int("line", c.Line))
	}

	return &LoadedScript{
		Path:     path,
		Source:   source,
		Metadata: *res.Meta,
	}, nil
}

// loadStageError tags an extraction error with a stage other than metadata.
type loadStageError struct {
	stage LoadStage
	err   error
}

func (e *loadStageError) Error() string { return e.err.Error() }
func (e *loadStageError) Unwrap() error { return e.err }

// ErrNoModuleExports is the extraction error for a script that exports
// nothing: module.exports is still the empty object the VM started with.
var ErrNoModuleExports = errors.New("script does not export anything (no module.exports)")

// handlerNames are the module.exports functions the runtime calls, per type.
var handlerNames = []string{"scanPerInsertionPoint", "scanPerRequest", "scanPerHost", "execute"}

// loadTimeout bounds a script's top-level code during load or lint, so a
// top-level infinite loop fails the load instead of hanging the scan. A var so
// tests can shorten it.
var loadTimeout = 10 * time.Second

// ExtractResult is what loading a script's top-level code reveals.
type ExtractResult struct {
	Meta *ScriptMetadata
	// TopLevelEffects lists the effectful vigolium.* calls the top-level code
	// made. They were stubbed (nothing was sent, read, written or run) and get
	// their real behaviour only inside handlers at scan time.
	TopLevelEffects []EffectCall
	// Handlers holds the handler names module.exports defines as functions.
	Handlers map[string]bool
}

// metadataExtractor extracts script metadata by running each script in a FRESH
// load-mode VM (SetupAPI with ModeLoad): the full vigolium.* surface is present,
// pure functions are real, and every effectful one is a recording stub. A
// previous version reused one VM across scripts and reset only module.exports,
// but top-level var/let/const/class/function declarations persist in the
// runtime's global scope — so a second script declaring the same identifier
// threw "already declared", making load order affect which scripts validated. A
// fresh VM per Extract eliminates that cross-script leakage.
type metadataExtractor struct {
	vars map[string]string // extensions.variables, exposed as vigolium.config
}

func newMetadataExtractor() *metadataExtractor {
	return &metadataExtractor{}
}

// Extract runs a script in a fresh load-mode VM and reads its module.exports
// metadata.
func (me *metadataExtractor) Extract(source, path string) (*ScriptMetadata, error) {
	res, err := me.extract(source, path)
	if err != nil {
		return nil, err
	}
	return res.Meta, nil
}

// extract is Extract plus the top-level effects and exported handlers.
func (me *metadataExtractor) extract(source, path string) (res *ExtractResult, err error) {
	prog, err := sobek.Compile(path, source, false)
	if err != nil {
		return nil, &loadStageError{stage: LoadStageCompile, err: err}
	}

	vm := sobek.New()
	exports := vm.NewObject()
	module := vm.NewObject()
	_ = module.Set("exports", exports)
	_ = vm.Set("module", module)
	_ = vm.Set("exports", exports)

	var effects []EffectCall
	SetupAPI(vm, APIOptions{
		Mode:         ModeLoad,
		ScriptID:     "load",
		ConfigVars:   me.vars,
		OnLoadEffect: func(c EffectCall) { effects = append(effects, c) },
	})

	// A handler that panics in Go (rather than throwing a JS error) must fail
	// this one script, not the process.
	defer func() {
		if p := recover(); p != nil {
			res, err = nil, fmt.Errorf("script execution error: panic: %v", p)
		}
	}()
	timer := time.AfterFunc(loadTimeout, func() {
		vm.Interrupt(fmt.Sprintf("top-level code exceeded %s at load time", loadTimeout))
	})
	_, runErr := vm.RunProgram(prog)
	timer.Stop()
	if runErr != nil {
		return nil, fmt.Errorf("script execution error: %w", runErr)
	}

	// Read module.exports
	exportsVal := module.Get("exports")
	if exportsVal == nil || sobek.IsUndefined(exportsVal) || sobek.IsNull(exportsVal) {
		return nil, ErrNoModuleExports
	}

	obj := exportsVal.ToObject(vm)
	if len(obj.Keys()) == 0 {
		return nil, ErrNoModuleExports
	}

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

	handlers := make(map[string]bool, len(handlerNames))
	for _, name := range handlerNames {
		if v := obj.Get(name); v != nil {
			if _, ok := sobek.AssertFunction(v); ok {
				handlers[name] = true
			}
		}
	}

	return &ExtractResult{Meta: meta, TopLevelEffects: effects, Handlers: handlers}, nil
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
