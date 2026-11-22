package main

import (
	"go/ast"
	"go/token"
	"go/types"
	"maps"
	"slices"
	"strings"

	"github.com/getlantern/radiance/internal/logsafe"
	"golang.org/x/tools/go/ast/inspector"
	"golang.org/x/tools/go/cfg"
	"golang.org/x/tools/go/types/typeutil"
)

// joinSource returns the lesser non-empty source, so reports don't depend on the order
// paths merge.
func joinSource(a, b string) string {
	if a == "" || b != "" && b < a {
		return b
	}
	return a
}

// taintState maps each local variable to the source of a secret it may hold; an absent
// variable holds none.
type taintState map[types.Object]string

func (s taintState) set(obj types.Object, source string) {
	if source == "" {
		delete(s, obj)
	} else {
		s[obj] = source
	}
}

// slogFuncs holds the slog functions and Logger methods that log their arguments.
var slogFuncs = map[string]bool{
	"Debug": true, "Info": true, "Warn": true, "Error": true,
	"DebugContext": true, "InfoContext": true, "WarnContext": true, "ErrorContext": true,
	"Log": true, "LogAttrs": true, "With": true, "WithGroup": true,
}

type taintChecker struct {
	reporter
	// switchVars maps the assignment of each type switch that declares a variable to
	// that variable's object in every clause.
	switchVars map[ast.Stmt][]types.Object
}

func checkSecretFlows(r reporter, insp *inspector.Inspector) {
	c := taintChecker{reporter: r, switchVars: map[ast.Stmt][]types.Object{}}
	insp.Preorder([]ast.Node{(*ast.TypeSwitchStmt)(nil)}, func(n ast.Node) {
		s := n.(*ast.TypeSwitchStmt)
		for _, clause := range s.Body.List {
			if obj := c.pass.TypesInfo.Implicits[clause]; obj != nil {
				c.switchVars[s.Assign] = append(c.switchVars[s.Assign], obj)
			}
		}
	})
	insp.Preorder([]ast.Node{(*ast.FuncDecl)(nil), (*ast.FuncLit)(nil)}, func(n ast.Node) {
		switch n := n.(type) {
		case *ast.FuncDecl:
			if n.Body != nil {
				c.checkBody(n.Body)
			}
		case *ast.FuncLit:
			c.checkBody(n.Body)
		}
	})
}

func (c taintChecker) checkBody(body *ast.BlockStmt) {
	graph := cfg.New(body, func(*ast.CallExpr) bool { return true })
	inputs := map[*cfg.Block]taintState{graph.Blocks[0]: {}}
	queue := []*cfg.Block{graph.Blocks[0]}
	for len(queue) > 0 {
		block := queue[0]
		queue = queue[1:]
		state := maps.Clone(inputs[block])
		c.bindRangeVars(block, state)
		for _, node := range block.Nodes {
			c.transfer(node, state)
		}
		for _, next := range block.Succs {
			previous, visited := inputs[next]
			merged := state
			if visited {
				merged = maps.Clone(previous)
				for obj, source := range state {
					merged.set(obj, joinSource(merged[obj], source))
				}
			}
			if !visited || !maps.Equal(previous, merged) {
				inputs[next] = merged
				queue = append(queue, next)
			}
		}
	}
	for _, block := range graph.Blocks {
		input, reachable := inputs[block]
		if !reachable {
			continue
		}
		state := maps.Clone(input)
		c.bindRangeVars(block, state)
		for _, node := range block.Nodes {
			ast.Inspect(node, func(n ast.Node) bool {
				if _, nested := n.(*ast.FuncLit); nested {
					return false
				}
				if call, ok := n.(*ast.CallExpr); ok {
					c.checkSlogCall(call, state)
				}
				return true
			})
			c.transfer(node, state)
		}
	}
}

func (c taintChecker) bindRangeVars(block *cfg.Block, state taintState) {
	if block.Kind != cfg.KindRangeBody {
		return
	}
	loop := block.Stmt.(*ast.RangeStmt)
	element := c.taintOf(loop.X, state)
	// The key carries the ranged value's taint, except for an index or a ranged-over integer.
	key := element
	if t := c.pass.TypesInfo.TypeOf(loop.X); t != nil {
		switch t.Underlying().(type) {
		case *types.Slice, *types.Array, *types.Pointer, *types.Basic:
			key = ""
		}
	}
	c.assign(loop.Key, key, state)
	c.assign(loop.Value, element, state)
}

func (c taintChecker) transfer(node ast.Node, state taintState) {
	var lhs, rhs []ast.Expr
	var compound bool
	switch n := node.(type) {
	case *ast.AssignStmt:
		if vars, ok := c.switchVars[n]; ok {
			operand := c.taintOf(n.Rhs[0].(*ast.TypeAssertExpr).X, state)
			for _, obj := range vars {
				state.set(obj, operand)
			}
			return
		}
		lhs, rhs = n.Lhs, n.Rhs
		compound = n.Tok != token.ASSIGN && n.Tok != token.DEFINE
	case *ast.ValueSpec:
		for _, name := range n.Names {
			lhs = append(lhs, name)
		}
		rhs = n.Values
	default:
		return
	}
	sources := make([]string, len(lhs))
	switch {
	case len(rhs) == 0:
	case len(rhs) < len(lhs):
		// The first value of a multi-value expression, any text results of a call, and the
		// error of a call whose error quotes its input carry its taint.
		whole := c.taintOf(rhs[0], state)
		results, _ := c.pass.TypesInfo.TypeOf(rhs[0]).(*types.Tuple)
		quoting := c.callErrorQuotesInput(rhs[0])
		for i := range sources {
			if i == 0 || results != nil && (holdsText(results.At(i).Type()) || quoting && isError(results.At(i).Type())) {
				sources[i] = whole
			}
		}
	default:
		for i := range sources {
			sources[i] = c.taintOf(rhs[i], state)
		}
	}
	for i, expr := range lhs {
		if compound {
			sources[i] = joinSource(sources[i], c.taintOf(expr, state))
		}
		c.assign(expr, sources[i], state)
	}
}

func (c taintChecker) callErrorQuotesInput(expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return false
	}
	fn, ok := typeutil.Callee(c.pass.TypesInfo, call).(*types.Func)
	return ok && fn.Pkg() != nil && errorQuotesInput(fn.Pkg().Path(), fn.Name())
}

// errorQuotesInput reports whether the function pkg.name returns an error, such as a
// strconv.NumError, url.Error or url.EscapeError, that quotes text it was given.
func errorQuotesInput(pkg, name string) bool {
	switch pkg {
	case "strconv":
		return name == "Atoi" || strings.HasPrefix(name, "Parse")
	case "net/url":
		switch name {
		case "Parse", "ParseRequestURI", "QueryUnescape", "PathUnescape":
			return true
		}
	}
	return false
}

func isBool(t types.Type) bool {
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Info()&types.IsBoolean != 0
}

func isError(t types.Type) bool {
	return types.Identical(t, types.Universe.Lookup("error").Type())
}

func (c taintChecker) assign(expr ast.Expr, source string, state taintState) {
	if id, ok := expr.(*ast.Ident); ok && id.Name != "_" {
		state.set(c.pass.TypesInfo.ObjectOf(id), source)
	}
}

// taintOf returns the source of a secret that expr may hold, or "" if it holds none.
func (c taintChecker) taintOf(expr ast.Expr, state taintState) string {
	info := c.pass.TypesInfo
	switch n := expr.(type) {
	case *ast.Ident:
		obj := info.ObjectOf(n)
		return joinSource(state[obj], secretVar(obj))
	case *ast.ParenExpr:
		return c.taintOf(n.X, state)
	case *ast.StarExpr:
		return c.taintOf(n.X, state)
	case *ast.UnaryExpr:
		if n.Op != token.NOT {
			return c.taintOf(n.X, state)
		}
	case *ast.TypeAssertExpr:
		return c.taintOf(n.X, state)
	case *ast.SelectorExpr:
		source := secretVar(info.ObjectOf(n.Sel))
		if n.Sel.Name == "Value" || n.Sel.Name == "Raw" {
			source = joinSource(source, cookieSource(info.TypeOf(n.X)))
		}
		if n.Sel.Name == "Value" && isNamed(info.TypeOf(n.X), "log/slog", "Attr") {
			source = joinSource(source, c.taintOf(n.X, state))
		}
		return source
	case *ast.IndexExpr:
		var source string
		if t := info.TypeOf(n.X); t != nil {
			if _, ok := t.Underlying().(*types.Map); ok {
				if key := constString(info, n.Index); logsafe.IsSecretKey(key) {
					source = "map key " + key
				}
			}
		}
		return joinSource(source, c.taintOf(n.X, state))
	case *ast.SliceExpr:
		return c.taintOf(n.X, state)
	case *ast.BinaryExpr:
		// A bool result reveals too little to report.
		if !isBool(info.TypeOf(n)) {
			return joinSource(c.taintOf(n.X, state), c.taintOf(n.Y, state))
		}
	case *ast.CompositeLit:
		return c.taintOfCompositeLit(n, state)
	case *ast.CallExpr:
		return c.taintOfCall(n, state)
	}
	return ""
}

// secretVar returns the source that a variable or field named as a secret introduces,
// or "" for any other object.
func secretVar(obj types.Object) string {
	v, ok := obj.(*types.Var)
	switch {
	case !ok || !logsafe.IsSecretKey(v.Name()):
		return ""
	case v.IsField():
		return "field " + v.Name()
	}
	return "variable " + v.Name()
}

func (c taintChecker) taintOfCompositeLit(lit *ast.CompositeLit, state taintState) string {
	_, isMap := c.pass.TypesInfo.TypeOf(lit).Underlying().(*types.Map)
	var source string
	for _, element := range lit.Elts {
		if pair, ok := element.(*ast.KeyValueExpr); ok {
			if isMap {
				source = joinSource(source, c.taintOf(pair.Key, state))
			}
			element = pair.Value
		}
		source = joinSource(source, c.taintOf(element, state))
	}
	return source
}

func (c taintChecker) taintOfCall(call *ast.CallExpr, state taintState) string {
	info := c.pass.TypesInfo
	if info.Types[call.Fun].IsType() {
		if len(call.Args) == 1 {
			return c.taintOf(call.Args[0], state)
		}
		return ""
	}
	callee := typeutil.Callee(info, call)
	if builtin, ok := callee.(*types.Builtin); ok {
		if builtin.Name() == "append" {
			return c.joinArgs(call.Args, state)
		}
		return ""
	}
	fn, _ := callee.(*types.Func)
	if fn == nil {
		return ""
	}
	if recv, args := c.receiverAndArgs(call); recv != nil && len(args) == 0 {
		switch name := fn.Name(); {
		case name == "Error" || name == "String":
			return joinSource(c.taintOf(recv, state), cookieSource(info.TypeOf(recv)))
		case logsafe.IsSecretKey(strings.TrimPrefix(name, "Get")):
			return "method " + name
		}
	}
	if fn.Pkg() == nil {
		return ""
	}
	pkg, name := fn.Pkg().Path(), fn.Name()
	var source string
	switch pkg {
	case "github.com/getlantern/radiance/common/settings":
		if strings.HasPrefix(name, "Get") && name != "GetStruct" && len(call.Args) > 0 {
			if key := constString(info, call.Args[0]); logsafe.IsSecretKey(key) {
				return "settings key " + key
			}
		}
	case "net/http":
		if _, args := c.receiverAndArgs(call); (name == "Get" || name == "Values") && len(args) == 1 && isMethodOf(fn, "net/http", "Header") {
			if key := constString(info, args[0]); logsafe.IsSecretKey(key) {
				return "header " + key
			}
		}
		if name == "BasicAuth" && isMethodOf(fn, "net/http", "Request") {
			return "http.Request.BasicAuth"
		}
	case "net/http/httputil":
		if strings.HasPrefix(name, "Dump") {
			return "httputil." + name
		}
	case "log/slog":
		return c.taintOfSlogCall(call, state)
	case "fmt":
		if spec, ok := fmtFuncs[name]; ok {
			verbs := callVerbs(info, call, spec)
			for i, arg := range call.Args {
				if i < spec.firstArg || !omitsValue(verbs[i-spec.firstArg], info.TypeOf(arg)) {
					source = joinSource(source, c.taintOf(arg, state))
					source = joinSource(source, cookieSource(info.TypeOf(arg)))
				}
			}
		}
	}
	if passesThrough(pkg, name, info.TypeOf(call)) {
		source = joinSource(source, c.joinArgs(call.Args, state))
	}
	return source
}

// taintOfSlogCall returns the source of a secret held by the slog.Value or slog.Attr
// that call builds or reads.
func (c taintChecker) taintOfSlogCall(call *ast.CallExpr, state taintState) string {
	info := c.pass.TypesInfo
	recv, args := c.receiverAndArgs(call)
	result := info.TypeOf(call)
	switch {
	case recv != nil && (isNamed(info.TypeOf(recv), "log/slog", "Value") || isNamed(info.TypeOf(recv), "log/slog", "Attr")):
		if isBool(result) {
			return ""
		}
		return c.taintOf(recv, state)
	case isNamed(result, "log/slog", "Value") || isNamed(result, "log/slog", "Attr"):
		return c.joinArgs(args, state)
	}
	return ""
}

func (c taintChecker) joinArgs(args []ast.Expr, state taintState) string {
	var source string
	for _, arg := range args {
		source = joinSource(source, c.taintOf(arg, state))
	}
	return source
}

// receiverAndArgs returns the receiver of a method call, or nil for a function call,
// and the arguments after it, taking a method expression's first argument as its
// receiver.
func (c taintChecker) receiverAndArgs(call *ast.CallExpr) (ast.Expr, []ast.Expr) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil, call.Args
	}
	switch selection := c.pass.TypesInfo.Selections[sel]; {
	case selection == nil:
		return nil, call.Args
	case selection.Kind() == types.MethodExpr:
		return call.Args[0], call.Args[1:]
	}
	return sel.X, call.Args
}

// isMethodOf reports whether fn is a method of the named type pkg.name or of a pointer
// to it.
func isMethodOf(fn *types.Func, pkg, name string) bool {
	recv := fn.Signature().Recv()
	if recv == nil {
		return false
	}
	t := recv.Type()
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	return isNamed(t, pkg, name)
}

// cookieSource returns "cookie" if t is an http.Cookie reached through any pointers and
// slices, named or not, or "" otherwise. A cookie's String method prints its value.
func cookieSource(t types.Type) string {
	var seen []types.Type
	for t != nil && !slices.ContainsFunc(seen, func(s types.Type) bool { return types.Identical(s, t) }) {
		if isNamed(t, "net/http", "Cookie") {
			return "cookie"
		}
		seen = append(seen, t)
		switch u := t.Underlying().(type) {
		case *types.Pointer:
			t = u.Elem()
		case *types.Slice:
			t = u.Elem()
		default:
			return ""
		}
	}
	return ""
}

// passesThrough reports whether the function pkg.name, with result type result, is
// known to return its arguments' text.
func passesThrough(pkg, name string, result types.Type) bool {
	switch pkg {
	case "strings", "strconv", "bytes":
		if results, ok := result.(*types.Tuple); ok {
			for v := range results.Variables() {
				if holdsText(v.Type()) || isError(v.Type()) && errorQuotesInput(pkg, name) {
					return true
				}
			}
			return false
		}
		return holdsText(result)
	case "errors":
		return name == "New" || name == "Join"
	case "net/url":
		switch name {
		case "QueryEscape", "PathEscape", "QueryUnescape", "PathUnescape", "Parse", "ParseRequestURI":
			return true
		}
	}
	return false
}

// holdsText reports whether a value of type t holds text: a string, or a slice of
// bytes, strings or such slices.
func holdsText(t types.Type) bool {
	var seen []types.Type
	for !slices.ContainsFunc(seen, func(s types.Type) bool { return types.Identical(s, t) }) {
		seen = append(seen, t)
		switch u := t.Underlying().(type) {
		case *types.Slice:
			if b, ok := u.Elem().Underlying().(*types.Basic); ok && b.Kind() == types.Byte {
				return true
			}
			t = u.Elem()
		case *types.Basic:
			return u.Info()&types.IsString != 0
		default:
			return false
		}
	}
	return false
}

func (c taintChecker) checkSlogCall(call *ast.CallExpr, state taintState) {
	fn, _ := typeutil.Callee(c.pass.TypesInfo, call).(*types.Func)
	if fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != "log/slog" || !slogFuncs[fn.Name()] {
		return
	}
	_, args := c.receiverAndArgs(call)
	if source := c.joinArgs(args, state); source != "" {
		c.reportf(call.Pos(), "slog.%s logs sensitive data from %s; log something that doesn't reveal it or add %s <reason>", fn.Name(), source, allowDirective)
	}
}
