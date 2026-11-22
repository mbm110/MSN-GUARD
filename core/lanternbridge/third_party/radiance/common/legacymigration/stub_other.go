//go:build !windows

package legacymigration

import (
	"context"
	"errors"
)

// Import is unavailable outside Windows.
func Import(context.Context, string, string, string, string, Verify, func(string) error) error {
	return errors.New("legacy migration requires Windows")
}
