//go:build !darwin

package vpn

import "context"

// newSourceCheck is nil where there is no stale source checker.
var newSourceCheck func(ctx context.Context, monitor defaultInterfaceMonitor) sourceCheckFunc
