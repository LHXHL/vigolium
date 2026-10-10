package modules

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/oast/oastclass"
)

// TestOASTCallSitesUseExplicitClass walks every module source file and checks
// each OAST callback URL is minted with an explicit, non-generic class:
//
//   - no module calls OASTProvider.GenerateURL (whose class is guessed from the
//     free-form label);
//   - every modkit.OASTURLFor call passes an oastclass.<Name> constant naming a
//     known class other than Generic.
//
// This is what keeps callback severity independent of label wording.
func TestOASTCallSitesUseExplicitClass(t *testing.T) {
	var files []string
	for _, dir := range []string{"active", "passive"} {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	if len(files) < 100 {
		t.Fatalf("found only %d module source files; the walk is broken", len(files))
	}

	fset := token.NewFileSet()
	minted := 0
	for _, path := range files {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch {
			case sel.Sel.Name == "GenerateURL" && len(call.Args) == 5:
				t.Errorf("%s: OAST URL minted with GenerateURL; use modkit.OASTURLFor(oast, oastclass.<Class>, ...) so callbacks are rated by class, not label wording",
					fset.Position(call.Pos()))
			case isIdent(sel.X, "modkit") && sel.Sel.Name == "OASTURLFor":
				minted++
				if len(call.Args) < 2 {
					t.Errorf("%s: malformed OASTURLFor call", fset.Position(call.Pos()))
					return true
				}
				cls, ok := call.Args[1].(*ast.SelectorExpr)
				if !ok || !isIdent(cls.X, "oastclass") {
					t.Errorf("%s: OASTURLFor class must be an oastclass.<Name> constant", fset.Position(call.Pos()))
					return true
				}
				if c, known := oastClassConsts[cls.Sel.Name]; !known {
					t.Errorf("%s: oastclass.%s is not a known class constant", fset.Position(call.Pos()), cls.Sel.Name)
				} else if c == oastclass.Generic {
					t.Errorf("%s: module OAST payloads must name a specific class, not oastclass.Generic", fset.Position(call.Pos()))
				}
			}
			return true
		})
	}
	if minted < 20 {
		t.Errorf("found only %d OASTURLFor call sites; expected the OAST modules to use it", minted)
	}
}

// oastClassConsts maps oastclass constant identifiers to their values, so the
// AST check can resolve oastclass.<Name>. A class added to oastclass.All()
// without an entry here fails TestOASTClassConstsComplete.
var oastClassConsts = map[string]oastclass.Class{
	"SSRF": oastclass.SSRF, "SSRFSmuggle": oastclass.SSRFSmuggle, "XXE": oastclass.XXE,
	"CMDI": oastclass.CMDI, "SQLi": oastclass.SQLi, "JWTKeyURL": oastclass.JWTKeyURL,
	"HostRouting": oastclass.HostRouting, "HeaderHarvest": oastclass.HeaderHarvest,
	"PasswordResetPoisoning": oastclass.PasswordResetPoisoning,
	"BlindXSS":               oastclass.BlindXSS, "SSTI": oastclass.SSTI, "Deserialization": oastclass.Deserialization,
	"JNDI": oastclass.JNDI, "Text4Shell": oastclass.Text4Shell, "ESI": oastclass.ESI,
	"SMTP": oastclass.SMTP, "MCPArg": oastclass.MCPArg, "Generic": oastclass.Generic,
}

func TestOASTClassConstsComplete(t *testing.T) {
	seen := make(map[oastclass.Class]bool, len(oastClassConsts))
	for _, c := range oastClassConsts {
		seen[c] = true
	}
	for _, c := range oastclass.All() {
		if !seen[c] {
			t.Errorf("oastclass %q has no entry in oastClassConsts", c)
		}
	}
}

func isIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}
