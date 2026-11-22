//go:build !windows

package serviceowner

import "errors"

// Load returns an empty owner outside Windows.
func Load() (string, error) { return "", nil }

// Save is unavailable outside Windows.
func Save(string) error { return errors.New("service ownership requires Windows") }

// GrantProcessQuery has no effect outside Windows.
func GrantProcessQuery() error { return nil }
