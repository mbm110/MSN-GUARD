package composite

import "fmt"

//line remapped.go:100
func remapped(v any) {
	//logleak:ok remapped lines
	_ = fmt.Sprint(v)
	_ = fmt.Sprint(v) //logleak:ok remapped lines
}
