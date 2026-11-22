// Logleak reports unsafe composite formatting and local flows of secrets into slog.
// Neither check runs on package main, test files or generated files. A //logleak:ok
// comment with a reason, at the end of a reported line or alone on the line above it,
// allows a deliberate case.
//
// The composite-formatting check covers the string-building fmt functions (Sprint*,
// Errorf and Append*), except calls that spread their arguments. It reports a value
// whose formatting may print the contents of a struct, map or interface. Error and
// String methods that the verb calls are trusted, except beneath a fmt.Formatter, whose
// Format method may print anything, including what a pointer refers to.
//
// Secret tracking follows fields, variables, getter methods, constant map keys, settings
// keys and HTTP header keys named as secrets, along with basic auth credentials, cookie
// values and httputil dumps, through local data flow within a function body. It does not
// follow data into called functions, beyond Error and String methods and known fmt,
// strings, bytes, strconv, errors, net/url and slog helpers, nor through struct fields,
// captured variables or heap writes. A secret is reported wherever it is logged, even
// under a key or group that a handler might redact.
package main

import (
	"bytes"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/singlechecker"
	"golang.org/x/tools/go/ast/inspector"
)

var analyzer = &analysis.Analyzer{
	Name: "logleak",
	Doc:  "reports unsafe composite formatting and local flows of secrets into slog",
	Run:  run,
}

const allowDirective = "//logleak:ok"

type fileLine struct {
	file string
	line int
}

type allowedLines map[fileLine]bool

func (a allowedLines) allows(pos token.Position) bool {
	return a[fileLine{pos.Filename, pos.Line}]
}

type reporter struct {
	pass    *analysis.Pass
	allowed allowedLines
}

func (r reporter) reportf(pos token.Pos, format string, args ...any) {
	if !r.allowed.allows(r.pass.Fset.PositionFor(pos, false)) {
		r.pass.Reportf(pos, format, args...)
	}
}

func run(pass *analysis.Pass) (any, error) {
	if pass.Pkg.Name() == "main" {
		return nil, nil
	}
	r := reporter{pass: pass, allowed: allowedLines{}}
	var files []*ast.File
	for _, f := range pass.Files {
		tf := pass.Fset.File(f.Pos())
		if ast.IsGenerated(f) || strings.HasSuffix(tf.Name(), "_test.go") {
			continue
		}
		files = append(files, f)
		src, err := pass.ReadFile(tf.Name())
		if err != nil {
			return nil, err
		}
		for _, group := range f.Comments {
			for _, c := range group.List {
				d, ok := ast.ParseDirective(c.Slash, c.Text)
				if ok && d.Tool == "logleak" && d.Name == "ok" && d.Args != "" {
					r.allowed[fileLine{tf.Name(), directiveLine(tf, src, c)}] = true
				}
			}
		}
	}

	insp := inspector.New(files)
	checkSecretFlows(r, insp)
	checkCompositeFormatting(r, insp)
	return nil, nil
}

// directiveLine returns the line that the directive c in src covers: its own line when
// it follows code, or the next line when it stands alone.
func directiveLine(tf *token.File, src []byte, c *ast.Comment) int {
	line := tf.PositionFor(c.Pos(), false).Line
	if len(bytes.TrimSpace(src[tf.Offset(tf.LineStart(line)):tf.Offset(c.Pos())])) == 0 {
		line++
	}
	return line
}

func constString(info *types.Info, expr ast.Expr) string {
	v := info.Types[expr].Value
	if v != nil && v.Kind() == constant.String {
		return constant.StringVal(v)
	}
	return ""
}

func isNamed(t types.Type, pkg, name string) bool {
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == pkg && named.Obj().Name() == name
}

func main() { singlechecker.Main(analyzer) }
