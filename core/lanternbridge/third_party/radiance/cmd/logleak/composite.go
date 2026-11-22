package main

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/ast/inspector"
	"golang.org/x/tools/go/types/typeutil"
)

var (
	errorType    = types.Universe.Lookup("error").Type().Underlying().(*types.Interface)
	stringerType = types.NewInterfaceType([]*types.Func{
		types.NewFunc(token.NoPos, nil, "String", types.NewSignatureType(nil, nil, nil, nil,
			types.NewTuple(types.NewVar(token.NoPos, nil, "", types.Typ[types.String])), false)),
	}, nil).Complete()
)

func checkCompositeFormatting(r reporter, insp *inspector.Inspector) {
	info := r.pass.TypesInfo
	insp.Preorder([]ast.Node{(*ast.CallExpr)(nil)}, func(n ast.Node) {
		call := n.(*ast.CallExpr)
		fn, ok := typeutil.Callee(info, call).(*types.Func)
		if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "fmt" {
			return
		}
		spec, ok := fmtFuncs[fn.Name()]
		if !ok || call.Ellipsis.IsValid() {
			return
		}
		args := call.Args[min(spec.firstArg, len(call.Args)):]
		verbs := callVerbs(info, call, spec)
		if len(args) == 0 && len(call.Args) == 1 {
			if _, multi := info.TypeOf(call.Args[0]).(*types.Tuple); multi {
				// A multi-value argument supplies every value, including any format
				// string, whose verbs are then unknown.
				verb := byte('v')
				if spec.formatArg >= 0 {
					verb = verbUnknown
				}
				args, verbs = call.Args, []byte{verb}
			}
		}
		for i, arg := range args {
			t := info.TypeOf(arg)
			if omitsValue(verbs[i], t) || !dumpsComposite(t, callsErrorOrString(fn.Name(), verbs[i], t), true) {
				continue
			}
			r.reportf(arg.Pos(), "fmt.%s formats %s, which can carry secrets past log redaction; format its fields or add %s <reason>",
				fn.Name(), types.TypeString(t, types.RelativeTo(r.pass.Pkg)), allowDirective)
		}
	})
}

// callsErrorOrString reports whether verb, used by the fmt function named fn, makes fmt
// call an error's Error or a Stringer's String method. %w calls Error only when Errorf
// formats an error; otherwise fmt prints the value itself.
func callsErrorOrString(fn string, verb byte, t types.Type) bool {
	if verb == 'w' {
		return fn == "Errorf" && types.Implements(t, errorType)
	}
	return strings.IndexByte("vsxXq", verb) >= 0
}

// dumpsComposite reports whether fmt may print the contents of a struct, map or
// interface held in a value of type t. usesMethod reports whether the verb calls an
// error's Error or a Stringer's String method, which a fmt.Formatter's Format method
// takes precedence over. topLevel reports whether t is an argument's type, the only
// place fmt follows a pointer to an array, slice, struct or map.
func dumpsComposite(t types.Type, usesMethod, topLevel bool) bool {
	return dumpsCompositeOnPath(t, usesMethod, topLevel, false, nil)
}

// dumpsCompositeOnPath is dumpsComposite for a type reached through the named types and
// type parameters on path, and beneath a fmt.Formatter if formatted, whose Format method
// may follow any pointer. A type that contains itself adds nothing the first visit did
// not report.
func dumpsCompositeOnPath(t types.Type, usesMethod, topLevel, formatted bool, path []types.Type) bool {
	switch u := types.Unalias(t).(type) {
	case *types.Named, *types.TypeParam:
		for _, prev := range path {
			if types.Identical(prev, u) {
				return false
			}
		}
		path = append(path[:len(path):len(path)], u)
	}
	switch {
	case t == nil:
		return false
	case isFormatter(t):
		// Format may print anything, so no Error or String method beneath it is trusted.
		usesMethod, formatted = false, true
	}
	// Check a type parameter's terms before its String or Error method: a type admitted by
	// a ~ term may have a Format method, which fmt calls instead.
	if tp, ok := types.Unalias(t).(*types.TypeParam); ok {
		if terms, restricted := typeTerms(tp.Constraint().Underlying().(*types.Interface)); restricted {
			for _, term := range terms {
				if dumpsCompositeOnPath(term.Type(), usesMethod && !term.Tilde(), topLevel, formatted || term.Tilde(), path) {
					return true
				}
			}
			return false
		}
	}
	if usesMethod && (types.Implements(t, errorType) || types.Implements(t, stringerType)) {
		return false
	}
	switch u := t.Underlying().(type) {
	case *types.Tuple:
		for v := range u.Variables() {
			if dumpsCompositeOnPath(v.Type(), usesMethod, true, formatted, path) {
				return true
			}
		}
	case *types.Slice:
		return dumpsCompositeOnPath(u.Elem(), usesMethod, false, formatted, path)
	case *types.Array:
		return dumpsCompositeOnPath(u.Elem(), usesMethod, false, formatted, path)
	case *types.Pointer:
		if formatted {
			return dumpsCompositeOnPath(u.Elem(), usesMethod, false, formatted, path)
		}
		if topLevel {
			switch u.Elem().Underlying().(type) {
			case *types.Array, *types.Slice, *types.Struct, *types.Map:
				return dumpsCompositeOnPath(u.Elem(), usesMethod, false, formatted, path)
			}
		}
	case *types.Map, *types.Struct, *types.Interface:
		return true
	}
	return false
}

// typeTerms returns the terms of the types a type parameter constrained by iface may
// have, or false if the constraint does not limit them to a list. It returns the terms
// of every embedded union, which may admit more types than their intersection does.
func typeTerms(iface *types.Interface) ([]*types.Term, bool) {
	var terms []*types.Term
	restricted := false
	for embedded := range iface.EmbeddedTypes() {
		if union, ok := unionTerms(embedded); ok {
			terms = append(terms, union...)
			restricted = true
		}
	}
	return terms, restricted
}

// unionTerms returns the terms of the union or type t, or false if t, or any of its
// terms, is an interface that does not limit its types to a list.
func unionTerms(t types.Type) ([]*types.Term, bool) {
	u, ok := t.(*types.Union)
	if !ok {
		if iface, ok := t.Underlying().(*types.Interface); ok {
			return typeTerms(iface)
		}
		return []*types.Term{types.NewTerm(false, t)}, true
	}
	var terms []*types.Term
	for term := range u.Terms() {
		if _, ok := term.Type().Underlying().(*types.Interface); !ok {
			terms = append(terms, term)
			continue
		}
		inner, ok := unionTerms(term.Type())
		if !ok {
			return nil, false
		}
		terms = append(terms, inner...)
	}
	return terms, true
}

func isFormatter(t types.Type) bool {
	obj, _, _ := types.LookupFieldOrMethod(t, false, nil, "Format")
	fn, ok := obj.(*types.Func)
	if !ok {
		return false
	}
	sig := fn.Signature()
	return sig.Results().Len() == 0 && sig.Params().Len() == 2 &&
		isNamed(sig.Params().At(0).Type(), "fmt", "State") &&
		types.Identical(sig.Params().At(1).Type(), types.Typ[types.Rune])
}
