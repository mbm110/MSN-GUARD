package fileperm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	modulePath     = "github.com/getlantern/radiance"
	filepermPath   = modulePath + "/common/fileperm"
	atomicfilePath = modulePath + "/common/atomicfile"
)

// modeArgs maps a package path and function to the index of its file mode
// argument; -1 means the function picks a mode itself.
var modeArgs = map[string]map[string]int{
	"os": {
		"WriteFile": 2,
		"OpenFile":  2,
		"Chmod":     1,
		"Create":    -1,
	},
	atomicfilePath: {
		"WriteFile": 2,
	},
}

var allowedFiles = map[string]string{
	"cmd/lanternd/lanternd.go":        "installs the lanternd executable, which must be executable",
	"cmd/lanternd/lanternd_linux.go":  "installs the systemd unit, which systemd must read",
	"cmd/lanternd/lanternd_darwin.go": "installs the launchd plist, which launchd must read",
	"ipc/socket.go":                   "the IPC socket's mode controls which users can connect",
	"ipc/socket_mobile.go":            "the IPC socket's mode controls which users can connect",
	"cmd/kindling-tester/main.go":     "test tool output",
}

// TestFileModesComeFromFileperm fails when non-test code passes a function in
// modeArgs a file mode that is not a fileperm constant, so permissions stay
// decided in one place.
func TestFileModesComeFromFileperm(t *testing.T) {
	root := moduleRoot(t)
	seen := make(map[string]bool)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "testdata" || name == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		modes := hardCodedModes(t, path)
		if _, ok := allowedFiles[rel]; ok {
			seen[rel] = true
			if len(modes) == 0 {
				t.Errorf("%s sets no hard-coded file mode; remove it from allowedFiles", rel)
			}
			return nil
		}
		for _, v := range modes {
			t.Errorf("%s:%s: use a fileperm constant for the file mode, or add the file to allowedFiles with a reason", rel, v)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for rel := range allowedFiles {
		if !seen[rel] {
			t.Errorf("%s in allowedFiles does not exist", rel)
		}
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

// hardCodedModes returns the positions of calls in the file at path that set
// a file mode other than a fileperm constant.
func hardCodedModes(t *testing.T, path string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	imports := make(map[string]string)
	for _, imp := range file.Imports {
		importPath, _ := strconv.Unquote(imp.Path.Value)
		name := importPath[strings.LastIndex(importPath, "/")+1:]
		if imp.Name != nil {
			name = imp.Name.Name
		}
		imports[name] = importPath
	}
	filepermConsts := filepermConstants(file, imports)

	var found []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		index, ok := modeArgs[imports[pkg.Name]][sel.Sel.Name]
		if !ok {
			return true
		}
		if index < 0 || index >= len(call.Args) || !isFilepermMode(call.Args[index], imports, filepermConsts) {
			found = append(found, strconv.Itoa(fset.Position(call.Pos()).Line))
		}
		return true
	})
	return found
}

func filepermConstants(file *ast.File, imports map[string]string) map[string]bool {
	consts := make(map[string]bool)
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			value := spec.(*ast.ValueSpec)
			for i, name := range value.Names {
				if i < len(value.Values) && isFilepermMode(value.Values[i], imports, nil) {
					consts[name.Name] = true
				}
			}
		}
	}
	return consts
}

func isFilepermMode(expr ast.Expr, imports map[string]string, consts map[string]bool) bool {
	switch e := expr.(type) {
	case *ast.SelectorExpr:
		pkg, ok := e.X.(*ast.Ident)
		return ok && imports[pkg.Name] == filepermPath
	case *ast.Ident:
		return consts[e.Name]
	}
	return false
}
