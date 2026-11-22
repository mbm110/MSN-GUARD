package main

import (
	"fmt"
	"slices"
	"strings"
)

func formatBytes(b int64) string {
	const (
		kib = 1024
		mib = kib * 1024
		gib = mib * 1024
	)
	switch {
	case b >= gib:
		return fmt.Sprintf("%6.2f GiB", float64(b)/gib)
	case b >= mib:
		return fmt.Sprintf("%6.2f MiB", float64(b)/mib)
	case b >= kib:
		return fmt.Sprintf("%6.2f KiB", float64(b)/kib)
	default:
		return fmt.Sprintf("%6d B  ", b)
	}
}

func joinNonEmpty(sep string, parts ...string) string {
	out := slices.DeleteFunc(parts, func(p string) bool { return p == "" })
	return strings.Join(out, sep)
}
