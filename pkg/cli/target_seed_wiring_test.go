package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/input/source"
)

// cliRepoRoot walks up from this file to the module root.
func cliRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate module root (no go.mod found)")
		}
		dir = parent
	}
}

// TestExecuteNativeScanSeedsTargetsBeforeBuildingRunner is the structural guard
// for the -T/--target-file bug seedTargetsFromTargetFiles documents.
//
// The failure is the ABSENCE of a call, which no unit test of the helper itself
// can see: seedTargetsFromTargetFiles can be perfectly correct and still never
// run. So the wiring is asserted structurally — the promotion must happen inside
// executeNativeScan and BEFORE runner.New, which is the moment Options is frozen
// into the input source and the phases.
//
// The ordering matters in the other direction too: the promotion clears
// TargetsFilePaths, and printScanSummary / the -P fan-out dispatch both read it,
// so it must stay below them in the same function rather than moving up into
// runScanCmd.
func TestExecuteNativeScanSeedsTargetsBeforeBuildingRunner(t *testing.T) {
	path := filepath.Join(cliRepoRoot(t), "pkg", "cli", "scan.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	require.NoError(t, err, "parse scan.go")

	var body *ast.BlockStmt
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == "executeNativeScan" && fn.Recv == nil {
			body = fn.Body
			break
		}
	}
	require.NotNil(t, body, "executeNativeScan not found in scan.go")

	seedPos, runnerPos := token.NoPos, token.NoPos
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			if fn.Name == "seedTargetsFromTargetFiles" && !seedPos.IsValid() {
				seedPos = call.Pos()
			}
		case *ast.SelectorExpr:
			pkg, isIdent := fn.X.(*ast.Ident)
			if isIdent && pkg.Name == "runner" && fn.Sel.Name == "New" && !runnerPos.IsValid() {
				runnerPos = call.Pos()
			}
		}
		return true
	})

	require.True(t, seedPos.IsValid(),
		"executeNativeScan must call seedTargetsFromTargetFiles, or a -T/--target-file run leaves Options.Targets empty and the target-seeded phases (spidering seeds, deparos content discovery) silently do nothing")
	require.True(t, runnerPos.IsValid(), "executeNativeScan must build the runner via runner.New")
	require.Less(t, int(seedPos), int(runnerPos),
		"seedTargetsFromTargetFiles must run BEFORE runner.New — after it, Options is already frozen into the input source and the phases")
}

// TestStdinGateAdmitsEveryTargetListMode guards the same contract on the
// piped-input side. The stdin block is what lands a piped URL list in
// Options.Targets instead of a StdinSource the target-seeded phases never see,
// and it is entered on source.IsTargetListFormat(InputFileMode). The hole it
// replaced was a `!cmd.Flags().Changed("input-mode")` gate: an explicit `-I urls`
// declared a URL list and then skipped the promotion entirely.
//
// Asserted through the predicate rather than by walking the AST for a call — a
// symbol-reference check passes even when the call sits in a branch nothing
// reaches, which is exactly the failure being guarded against.
func TestStdinGateAdmitsEveryTargetListMode(t *testing.T) {
	// Unset (the -I default) and every spelling of the URL-list format.
	for _, mode := range []string{"", "urls", "url", "list"} {
		assert.True(t, source.IsTargetListFormat(mode),
			"stdin gate must admit -I %q, or a piped URL list never reaches Options.Targets", mode)
	}
	// A spec/export mode keeps its own parser and its StdinSource.
	for _, mode := range []string{"har", "openapi", "burpxml", "curl"} {
		assert.False(t, source.IsTargetListFormat(mode),
			"stdin gate must not divert -I %q into the URL-list promotion", mode)
	}
}
