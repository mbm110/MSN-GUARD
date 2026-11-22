package testutil

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// LoggedIdentifiers fails t for every slog call in the non-test Go files of
// dir whose arguments use an identifier forbidden reports true for. It is how
// a package shows that a value, such as a helper pairing ID, never reaches its
// logs, without replacing the default logger in a test.
func LoggedIdentifiers(t *testing.T, dir string, forbidden func(name string) bool) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	calls := 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatal(err)
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
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "slog" || !isLogFunc(sel.Sel.Name) {
				return true
			}
			calls++
			for _, arg := range call.Args {
				ast.Inspect(arg, func(n ast.Node) bool {
					if id, ok := n.(*ast.Ident); ok && forbidden(id.Name) {
						t.Errorf("%s: slog.%s logs %s", fset.Position(id.Pos()), sel.Sel.Name, id.Name)
					}
					return true
				})
			}
			return true
		})
	}
	if calls == 0 {
		t.Fatalf("no slog calls found in %s", dir)
	}
}

func isLogFunc(name string) bool {
	switch name {
	case "Debug", "Info", "Warn", "Error", "Log", "DebugContext", "InfoContext", "WarnContext", "ErrorContext", "LogAttrs":
		return true
	}
	return false
}
