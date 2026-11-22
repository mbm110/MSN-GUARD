package main

import (
	"bytes"
	"go/ast"
	"go/types"
	"strings"
)

var fmtFuncs = map[string]fmtSpec{
	"Sprint": {-1, 0}, "Sprintln": {-1, 0}, "Sprintf": {0, 1}, "Errorf": {0, 1},
	"Append": {-1, 1}, "Appendln": {-1, 1}, "Appendf": {1, 2},
}

// fmtSpec gives the index of a fmt function's format string, or -1 if it has none, and
// of its first formatted argument.
type fmtSpec struct{ formatArg, firstArg int }

// Pseudo-verbs that parseVerbs records in place of a format verb.
const (
	// verbUnknown must be zero, the value parseVerbs leaves when it cannot map a verb.
	verbUnknown byte = 0
	verbSharpV  byte = '#'
	verbStarArg byte = '*'
)

// callVerbs returns the verb formatting each of call's arguments from spec.firstArg on,
// as parseVerbs does, or 'v' for each if the function takes no format string. A
// non-constant format or spread arguments yield verbUnknown for each.
func callVerbs(info *types.Info, call *ast.CallExpr, spec fmtSpec) []byte {
	n := max(len(call.Args)-spec.firstArg, 0)
	switch {
	case call.Ellipsis.IsValid() || len(call.Args) <= spec.formatArg:
		return make([]byte, n)
	case spec.formatArg < 0:
		return bytes.Repeat([]byte{'v'}, n)
	}
	return parseVerbs(constString(info, call.Args[spec.formatArg]), n)
}

// omitsValue reports whether verb leaves a value of type t out of fmt's output.
func omitsValue(verb byte, t types.Type) bool {
	return verb == verbStarArg || verb == 'T' || verb == 'p' && printsAsAddress(t)
}

// parseVerbs returns the verb that formats each argument, verbSharpV for %#v, or
// verbStarArg for one consumed by a '*' width or precision. An explicit argument index
// makes the mapping unknown, so it returns all verbUnknown.
func parseVerbs(format string, n int) []byte {
	verbs := make([]byte, n)
	arg := 0
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		i++
		sharp := false
		for i < len(format) && strings.IndexByte("+-# 0", format[i]) >= 0 {
			sharp = sharp || format[i] == '#'
			i++
		}
		for i < len(format) && (format[i] == '*' || format[i] == '.' || '0' <= format[i] && format[i] <= '9') {
			if format[i] == '*' && arg < n {
				verbs[arg] = verbStarArg
				arg++
			}
			i++
		}
		if i >= len(format) {
			break
		}
		switch format[i] {
		case '%':
			continue
		case '[':
			return make([]byte, n)
		}
		if arg < n {
			verbs[arg] = format[i]
			if sharp && format[i] == 'v' {
				verbs[arg] = verbSharpV
			}
		}
		arg++
	}
	return verbs
}

// printsAsAddress reports whether %p is known to print a value of type t as an address.
// For any other concrete type, fmt reports a bad verb and prints the value itself.
func printsAsAddress(t types.Type) bool {
	switch u := t.Underlying().(type) {
	case *types.Pointer, *types.Map, *types.Slice, *types.Chan, *types.Signature:
		return true
	case *types.Basic:
		return u.Kind() == types.UnsafePointer
	}
	return false
}
