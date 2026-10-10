package runner

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/jsext"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// ExtensionLoadError is the scan's error when an extension the user named
// directly (--ext, extensions.custom_dir) failed to load and
// --ext-allow-failures was not given. It is returned before any target traffic,
// so a dropped extension can never make a scan look clean. The CLI exits 2 with
// error.code extension_load_failed.
type ExtensionLoadError struct {
	Failures []jsext.LoadFailure
}

func (e *ExtensionLoadError) Error() string {
	parts := make([]string, 0, len(e.Failures))
	for _, f := range e.Failures {
		parts = append(parts, fmt.Sprintf("%s (%s): %v", f.Path, f.Stage, f.Err))
	}
	return fmt.Sprintf("%d extension(s) named with --ext failed to load: %s; fix them (vigolium ext lint <file>) or pass --ext-allow-failures to scan without them",
		len(e.Failures), strings.Join(parts, "; "))
}

// Code reports the stable error code (see classifyErrorCode in pkg/cli).
func (e *ExtensionLoadError) Code() apicontract.ErrorCode {
	return apicontract.CodeExtensionLoadFailed
}

// reportExtensionFailures announces every extension that failed to load — an
// extension.failed event and one stderr line each — and returns an
// *ExtensionLoadError when any of them was named explicitly, unless the
// settings allow load failures. Directory-discovered failures never stop the
// scan; persistExtensionFailures puts them on the scan row.
func (r *Runner) reportExtensionFailures(engine *jsext.Engine) error {
	if engine == nil {
		return nil
	}
	failures := engine.Failures()
	if len(failures) == 0 {
		return nil
	}
	for _, f := range failures {
		explicit := f.Explicit
		scanevents.Emit(scanevents.Event{
			Type:     scanevents.TypeExtensionFailed,
			ModuleID: f.ID,
			Path:     f.Path,
			Stage:    string(f.Stage),
			Explicit: &explicit,
			Message:  loadErrText(f.Err),
		})
		zap.L().Warn("Extension failed to load",
			zap.String("path", f.Path), zap.String("stage", string(f.Stage)),
			zap.Bool("explicit", f.Explicit), zap.Error(f.Err))
		if !r.options.Silent {
			fmt.Fprintf(os.Stderr, "  %s extension %s failed to load (%s): %s\n",
				terminal.Yellow(terminal.SymbolWarning), terminal.Cyan(f.Path), f.Stage, loadErrText(f.Err))
		}
	}

	explicit := engine.ExplicitFailures()
	if len(explicit) == 0 {
		return nil
	}
	if r.settings != nil && r.settings.DynamicAssessment.Extensions.AllowLoadFailures {
		zap.L().Warn("Continuing without explicitly requested extensions (--ext-allow-failures)",
			zap.Int("failed", len(explicit)))
		return nil
	}
	return &ExtensionLoadError{Failures: explicit}
}

// persistExtensionFailures records the extensions that failed to load on the
// scan row (scans.extensions_failed), which scan.finished and `scan status`
// read back. Paths, in load order.
func (r *Runner) persistExtensionFailures(ctx context.Context, infra *phaseInfra) {
	if r.repository == nil || infra == nil || infra.jsEngine == nil {
		return
	}
	failures := infra.jsEngine.Failures()
	if len(failures) == 0 {
		return
	}
	paths := make([]string, 0, len(failures))
	for _, f := range failures {
		paths = append(paths, f.Path)
	}
	if err := r.repository.UpdateScanPartial(ctx, &database.Scan{
		UUID:             infra.scanUUID,
		ExtensionsFailed: paths,
	}); err != nil {
		zap.L().Warn("Failed to record failed extensions on scan", zap.Error(err))
	}
}

func loadErrText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
