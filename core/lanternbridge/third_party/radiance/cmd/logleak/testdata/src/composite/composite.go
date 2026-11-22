package composite

import (
	"errors"
	"fmt"
	"os"
	"time"
)

type cfg struct{ Password string }

type tag string

type named struct{ Secret string }

func (named) String() string { return "named" }

func f(c cfg, p *cfg, m map[string]string, cs []cfg, s []string, b []byte, v any, err error, d time.Duration, ds []time.Duration, n int, t tag, nm named) {
	_ = fmt.Sprintf("%v", c)               // want `fmt.Sprintf formats cfg, which can carry secrets past log redaction`
	_ = fmt.Sprintf("%s", m)               // want `fmt.Sprintf formats map\[string\]string`
	_ = fmt.Sprint(cs)                     // want `fmt.Sprint formats \[\]cfg`
	_ = fmt.Errorf("x %+v", p)             // want `fmt.Errorf formats \*cfg`
	_ = fmt.Sprintf("%v", v)               // want `fmt.Sprintf formats any`
	_ = fmt.Appendf(nil, "%v", c)          // want `fmt.Appendf formats cfg`
	_ = fmt.Sprint(s, b, ds, d, t, n, err) // scalars, slices of scalars, Stringers and errors
	fmt.Fprintf(os.Stderr, "%v", c)        // writes to a stream, not a string
	fmt.Println(m)                         // writes to a stream, not a string
	_ = fmt.Sprintf("%T %p %p", c, p, m)   // %T prints the type, and %p an address
	_ = fmt.Sprintf("%p", c)               // want `fmt.Sprintf formats cfg`
	// '*' consumes an argument, so only the last c is formatted with its fields.
	_ = fmt.Sprintf("%*d %T %v", n, n, c, c)       // want `fmt.Sprintf formats cfg`
	_ = fmt.Sprintf("%v %s %q %x", nm, nm, nm, nm) // String is called
	_ = fmt.Sprint(nm)                             // String is called
	_ = fmt.Sprintf("%#v", nm)                     // want `fmt.Sprintf formats named`
	_ = fmt.Sprintf("%d", nm)                      // want `fmt.Sprintf formats named`
	_ = fmt.Errorf("%w", nm)                       // want `fmt.Errorf formats named`
	_ = fmt.Sprintf("%w", err)                     // want `fmt.Sprintf formats error`
	_ = fmt.Errorf("wrap: %w", err)
	_ = errors.New(fmt.Sprintf("%d", n))
	// An explicit argument index makes the verb-to-argument mapping unknown.
	_ = fmt.Sprintf("%[1]T", c) // want `fmt.Sprintf formats cfg`
	_ = fmt.Sprint(v)           //logleak:ok recovered panic value
	//logleak:ok settings values are scalars
	_ = fmt.Sprint(v)
	//logleak:ok
	_ = fmt.Sprint(v) // want `fmt.Sprint formats any`
	//logleak:okay a different directive
	_ = fmt.Sprint(v) // want `fmt.Sprint formats any`
}

type formatted struct{ Secret string }

func (formatted) Error() string { return "formatted" }

func (f formatted) Format(s fmt.State, verb rune) { fmt.Fprintf(s, "%+v", f.Secret) }

type level int

func (level) Format(s fmt.State, verb rune) {}

func formatters(fe formatted, lv level) {
	_ = fmt.Sprintf("%v", fe)        // want `fmt.Sprintf formats formatted`
	_ = fmt.Errorf("%w", fe)         // want `fmt.Errorf formats formatted`
	_ = fmt.Sprint([]formatted{fe})  // want `fmt.Sprint formats \[\]formatted`
	_ = fmt.Sprintf("%v %d", lv, lv) // a Formatter of a scalar type
}

type ptrFormatted struct{ Secret string }

func (*ptrFormatted) Format(s fmt.State, verb rune) {}

func (ptrFormatted) String() string { return "ptrFormatted" }

func pointerFormatters(pf ptrFormatted) {
	_ = fmt.Sprintf("%v", pf) // a value's method set lacks Format, so String is called
}

func pair() ([]byte, string) { return nil, "%v" }

func load() (cfg, error) { return cfg{}, nil }

func strs() (string, any) { return "%v", nil }

func multiValue() {
	_ = fmt.Appendf(pair())
	_ = fmt.Sprint(load())  // want `fmt.Sprint formats \(cfg, error\)`
	_ = fmt.Sprintf(strs()) // want `fmt.Sprintf formats \(string, any\)`
}

func trailingAllow(v any) {
	_ = fmt.Sprint(v) //logleak:ok covers only this line
	_ = fmt.Sprint(v) // want `fmt.Sprint formats any`
}

func bufErr() ([]byte, error) { return nil, nil }

func pointers(ps *string, pcs []*cfg, pm *map[string]string) {
	_ = fmt.Append(bufErr())
	_ = fmt.Sprintf("%v", ps)
	_ = fmt.Sprint(pcs)
	_ = fmt.Sprint(pm) // want `fmt.Sprint formats \*map\[string\]string`
	_ = fmt.Sprint(new([]string))
	_ = fmt.Sprint(new([]cfg))        // want `fmt.Sprint formats \*\[\]cfg`
	_ = fmt.Sprint([]*ptrFormatted{}) // want `fmt.Sprint formats \[\]\*ptrFormatted`
}

type valueFormatted []named

func (valueFormatted) Format(s fmt.State, verb rune) {}

type ptrLevel int

func (*ptrLevel) Format(s fmt.State, verb rune) {}

func valueFormatters(vf valueFormatted, pl *ptrLevel) {
	_ = fmt.Sprint(vf) // want `fmt.Sprint formats valueFormatted`
	_ = fmt.Sprint(pl)
}

type recursive []recursive

type ptrList []*ptrList

func (*ptrList) Format(s fmt.State, verb rune) {}

func recursiveTypes(r recursive, pl ptrList) {
	_ = fmt.Sprint(r)
	_ = fmt.Sprint(pl)
}

type box[T any] []T

type genList[T any] []genList[T]

type genPtr[T any] []*genPtr[T]

func (*genPtr[T]) Format(s fmt.State, verb rune) {}

type selfMap map[string]selfMap

func siblings() (named, valueFormatted) { return named{}, nil }

func recursiveGuards(nested box[box[cfg]], gl genList[int], gp genPtr[int], sm selfMap) {
	_ = fmt.Sprint(nested)     // want `fmt.Sprint formats box\[box\[cfg\]\]`
	_ = fmt.Sprint(siblings()) // want `fmt.Sprint formats \(named, valueFormatted\)`
	_ = fmt.Sprint(gl)
	_ = fmt.Sprint(gp)
	_ = fmt.Sprint(sm) // want `fmt.Sprint formats selfMap`
}

type ptrCfgs []*cfg

func (p ptrCfgs) Format(s fmt.State, verb rune) { fmt.Fprint(s, p[0]) }

func formatterPointers(pc ptrCfgs) {
	_ = fmt.Sprint(pc) // want `fmt.Sprint formats ptrCfgs`
}

type integer interface{ ~int | ~int64 }

type number interface {
	integer | ~float64
}

type stringerInt interface {
	~int
	fmt.Stringer
}

func generic[I integer, N number, S stringerInt, C ~struct{ Password string }, M interface{ ~int | cfg }, A any, R interface{ ~[]R }](i I, n N, s S, c C, m M, a A, r R) {
	_ = fmt.Sprint(i, n, s) // scalars, and a Stringer
	_ = fmt.Sprint(c)       // want `fmt.Sprint formats C`
	_ = fmt.Sprint(m)       // want `fmt.Sprint formats M`
	_ = fmt.Sprint(a)       // want `fmt.Sprint formats A`
	_ = fmt.Sprint(r)       // a slice of itself, whose only terms are slices
}

type cfgs []*cfg

func (c cfgs) Format(s fmt.State, _ rune) { fmt.Fprintf(s, "%+v", *c[0]) }

func tilde[T ~[]*cfg, E []*cfg](t T, e E) {
	_ = fmt.Sprint(t) // want `fmt.Sprint formats T`
	_ = fmt.Sprint(e) // only []*cfg itself, which prints addresses
}

func tildeStringer[T ~[]named, E []named](t T, e E) {
	_ = fmt.Sprint(t) // want `fmt.Sprint formats T`
	_ = fmt.Sprint(e) // String is called on each element
}

type stringerStruct interface {
	~struct{ Password string }
	fmt.Stringer
}

type stringerNamed interface {
	named
	fmt.Stringer
}

func stringerConstraints[S stringerStruct, N stringerNamed, A fmt.Stringer](s S, n N, a A) {
	_ = fmt.Sprint(s) // want `fmt.Sprint formats S`
	_ = fmt.Sprint(n) // only named itself, whose String is called
	_ = fmt.Sprint(a) // String is called, as on a fmt.Stringer interface
}
