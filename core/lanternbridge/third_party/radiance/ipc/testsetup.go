package ipc

import (
	_ "unsafe" // for go:linkname
)

var _testing bool

//go:linkname serverTestSetup github.com/getlantern/radiance/internal/testutil.ipc_serverTestSetup
func serverTestSetup(path string) {
	setSocketPathForTesting(path)
	_testing = true
}
