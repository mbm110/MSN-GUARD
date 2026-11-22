//go:build android || ios || (darwin && !standalone)

// Package fileperm provides the permission bits used when creating files owned by radiance.
package fileperm

import "os"

const File os.FileMode = 0o644
