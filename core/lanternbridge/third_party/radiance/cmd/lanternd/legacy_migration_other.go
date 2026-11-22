//go:build !windows

package main

import "errors"

func migrateLegacy(*migrateCmd) error {
	return errors.New("legacy migration requires Windows")
}
